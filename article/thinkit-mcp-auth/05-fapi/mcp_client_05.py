import asyncio
import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.parse
import uuid
from pathlib import Path

import httpx
import requests
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from flask import Flask, redirect, request, session

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))

# ============================================================
# Runtime stores for this hands-on application
# ============================================================

TOKEN_STORE = {}
REGISTERED_CLIENT = None

# ============================================================
# Configuration
# ============================================================

KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080")
REALM = os.getenv("REALM", "mcp-fapi2")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://localhost:3000/callback")
SCOPE = os.getenv("SCOPE", "openid profile")

CLIENT_PRIVATE_KEY_FILE = os.getenv("CLIENT_PRIVATE_KEY_FILE", "client-private.pem")
DPOP_PRIVATE_KEY_FILE = os.getenv("DPOP_PRIVATE_KEY_FILE", "dpop-private.pem")
RESOURCE_URL = os.getenv("RESOURCE_URL", "http://localhost:9000/mcp")

# DCR settings
DCR_INITIAL_ACCESS_TOKEN = os.getenv("DCR_INITIAL_ACCESS_TOKEN", "")
DCR_CLIENT_NAME = os.getenv("DCR_CLIENT_NAME", "FAPI MCP DCR Client")
DCR_CLIENT_INFO_FILE = os.getenv("DCR_CLIENT_INFO_FILE", "dcr_client_info.json")
DCR_REQUESTED_CLIENT_ID = os.getenv("DCR_REQUESTED_CLIENT_ID", "")
DCR_FORCE_REGISTER = os.getenv("DCR_FORCE_REGISTER", "false").lower() == "true"

ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{REALM}"
AUTH_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
PAR_ENDPOINT = f"{ISSUER}/protocol/openid-connect/ext/par/request"
DCR_ENDPOINT = f"{ISSUER}/clients-registrations/openid-connect"

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLIENT_JWK_KID = os.getenv("CLIENT_JWK_KID", "key-1")


# ============================================================
# Encoding and key helpers
# ============================================================

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def int_to_base64url(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return base64url_encode(value.to_bytes(byte_length, "big"))


def generate_pkce_pair() -> tuple[str, str]:
    code_verifier = base64url_encode(secrets.token_bytes(64))
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64url_encode(digest)
    return code_verifier, code_challenge


def load_private_key_bytes() -> bytes:
    with open(CLIENT_PRIVATE_KEY_FILE, "rb") as f:
        return f.read()


def load_client_private_key_object():
    with open(CLIENT_PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_dpop_private_key():
    with open(DPOP_PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def client_public_jwk() -> dict:
    """
    Create the public JWK used by Keycloak to verify private_key_jwt.
    This is registered dynamically through DCR as inline jwks.
    """
    public_key = load_client_private_key_object().public_key()
    numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": CLIENT_JWK_KID,
        "use": "sig",
        "alg": "PS256",
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
    }


def client_jwks() -> dict:
    return {"keys": [client_public_jwk()]}


def dpop_public_key_to_jwk(public_key) -> dict:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": int_to_base64url(numbers.x),
        "y": int_to_base64url(numbers.y),
    }


def create_ath(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64url_encode(digest)


# ============================================================
# DCR helpers
# ============================================================

def load_registered_client_from_file() -> dict | None:
    path = Path(DCR_CLIENT_INFO_FILE)
    if not path.exists() or DCR_FORCE_REGISTER:
        return None

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not data.get("client_id"):
        return None

    return data


def save_registered_client_to_file(client_info: dict) -> None:
    path = Path(DCR_CLIENT_INFO_FILE)
    with path.open("w", encoding="utf-8") as f:
        json.dump(client_info, f, indent=2, ensure_ascii=False)


def build_client_registration_metadata() -> dict:
    """
    OpenID Connect Dynamic Client Registration metadata.

    This application requests a confidential client that authenticates with
    private_key_jwt. The public key is supplied as inline JWKS, so no manual
    certificate/key registration is needed in Keycloak.
    """
    metadata = {
        "client_name": DCR_CLIENT_NAME,
        "application_type": "web",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "PS256",
        "jwks": client_jwks(),
    }

    if DCR_REQUESTED_CLIENT_ID:
        metadata["client_id"] = DCR_REQUESTED_CLIENT_ID

    return metadata


def register_client_with_keycloak() -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if DCR_INITIAL_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {DCR_INITIAL_ACCESS_TOKEN}"

    response = requests.post(
        DCR_ENDPOINT,
        headers=headers,
        json=build_client_registration_metadata(),
        timeout=15,
    )

    try:
        body = response.json()
    except Exception:
        body = {"raw_response": response.text}

    if response.status_code not in [200, 201]:
        raise RuntimeError(
            json.dumps(
                {
                    "error": "dynamic_client_registration_failed",
                    "dcr_endpoint": DCR_ENDPOINT,
                    "status_code": response.status_code,
                    "response": body,
                },
                indent=2,
                ensure_ascii=False,
            )
        )

    save_registered_client_to_file(body)
    return body


def ensure_registered_client() -> dict:
    global REGISTERED_CLIENT

    if REGISTERED_CLIENT and REGISTERED_CLIENT.get("client_id") and not DCR_FORCE_REGISTER:
        return REGISTERED_CLIENT

    stored = load_registered_client_from_file()
    if stored:
        REGISTERED_CLIENT = stored
        return REGISTERED_CLIENT

    REGISTERED_CLIENT = register_client_with_keycloak()
    return REGISTERED_CLIENT


def current_client_id() -> str:
    return ensure_registered_client()["client_id"]


# ============================================================
# JWT / DPoP helpers
# ============================================================

def create_client_assertion(audience: str, client_id: str | None = None) -> str:
    """
    Create private_key_jwt client assertion for the dynamically registered client.
    """
    cid = client_id or current_client_id()
    now = int(time.time())

    header = {
        "alg": "PS256",
        "typ": "JWT",
        "kid": CLIENT_JWK_KID,
    }

    payload = {
        "iss": cid,
        "sub": cid,
        "aud": audience,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
    }

    token = jwt.encode(header, payload, load_private_key_bytes())
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def create_dpop_proof(http_method: str, url: str, access_token: str | None = None) -> str:
    """
    Create DPoP proof JWT.

    Token endpoint / PAR endpoint proof:
      htm, htu, iat, jti

    MCP resource access proof:
      htm, htu, iat, jti, ath
    """
    private_key = load_dpop_private_key()
    public_jwk = dpop_public_key_to_jwk(private_key.public_key())
    now = int(time.time())

    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": public_jwk,
    }

    payload = {
        "htu": url,
        "htm": http_method.upper(),
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    if access_token:
        payload["ath"] = create_ath(access_token)

    token = jwt.encode(header, payload, private_key)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


class DPoPAuth(httpx.Auth):
    """
    Adds Authorization: DPoP <access_token> and a fresh DPoP proof to each
    FastMCP HTTP request. A fresh proof is needed to avoid jti replay failures.
    """

    def __init__(self, access_token: str):
        self.access_token = access_token

    def auth_flow(self, request):
        dpop_proof = create_dpop_proof(
            request.method,
            str(request.url),
            access_token=self.access_token,
        )
        request.headers["Authorization"] = f"DPoP {self.access_token}"
        request.headers["DPoP"] = dpop_proof
        yield request


# ============================================================
# MCP resource access
# ============================================================

async def call_mcp_server_async(access_token: str) -> dict:
    transport = StreamableHttpTransport(
        RESOURCE_URL,
        auth=DPoPAuth(access_token),
    )

    async with Client(transport) as client:
        result = await client.call_tool(
            "protected_echo",
            {"message": "hello from DCR FAPI MCP client"},
        )

    if hasattr(result, "structured_content") and result.structured_content:
        tool_data = result.structured_content
    elif hasattr(result, "data") and result.data:
        tool_data = result.data
    else:
        tool_data = {}

    return {
        "status": "success",
        "mcp_result": tool_data.get("message", "No message returned from MCP server"),
    }


def call_resource_server(access_token: str) -> dict:
    try:
        result = asyncio.run(call_mcp_server_async(access_token))
        return {"status_code": 200, "body": result}
    except Exception as e:
        return {
            "status_code": 500,
            "body": {
                "error": "mcp_tool_call_failed",
                "detail": str(e),
            },
        }


# ============================================================
# Flask routes
# ============================================================

@app.route("/")
def index():

    return """
    <h1>FAPI MCP Client</h1>

    <p>
        This demo automatically registers the OAuth client when needed,
        then obtains an access token for accessing the MCP Server.
    </p>

    <form action="/login" method="get">
        <button type="submit">
            Get access token for MCP Server
        </button>
    </form>

    <form action="/login-with-client-secret" method="get" style="margin-top: 0.5em;">
        <button type="submit">
            Get access token for MCP Server (with client secret)
        </button>
    </form>

    <form action="/reset-local-registration" method="post" style="margin-top: 1.5em;">
        <button type="submit">
            Reset local registered client info
        </button>
    </form>
    """


@app.route("/dcr-metadata-preview")
def dcr_metadata_preview():
    return build_client_registration_metadata()


@app.route("/local-jwks.json")
def local_jwks():
    return client_jwks()


@app.route("/registration-info")
def registration_info():
    return ensure_registered_client()


@app.route("/register-client", methods=["POST"])
def register_client_route():
    global REGISTERED_CLIENT
    REGISTERED_CLIENT = register_client_with_keycloak()
    return {
        "message": "client registered by DCR",
        "client_id": REGISTERED_CLIENT.get("client_id"),
        "registration_response": REGISTERED_CLIENT,
    }


@app.route("/reset-local-registration", methods=["POST"])
def reset_local_registration():
    global REGISTERED_CLIENT
    REGISTERED_CLIENT = None
    path = Path(DCR_CLIENT_INFO_FILE)
    if path.exists():
        path.unlink()
    return {
        "message": "local DCR registration cache cleared",
        "note": "This does not delete the client from Keycloak. Delete it manually if needed.",
    }


@app.route("/login")
def login():
    client_info = ensure_registered_client()
    client_id = client_info["client_id"]

    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    client_session_id = secrets.token_urlsafe(32)

    session["code_verifier"] = code_verifier
    session["state"] = state
    session["nonce"] = nonce
    session["client_session_id"] = client_session_id
    session["client_id"] = client_id
    # This is the normal flow. Reset any previous client_secret flow state.
    session["client_auth_method"] = "private_key_jwt"
    session.pop("client_secret", None)

    client_assertion = create_client_assertion(ISSUER, client_id=client_id)
    par_dpop_proof = create_dpop_proof("POST", PAR_ENDPOINT)

    par_response = requests.post(
        PAR_ENDPOINT,
        headers={"DPoP": par_dpop_proof},
        data={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": client_assertion,
        },
        timeout=10,
    )

    try:
        par_body = par_response.json()
    except Exception:
        par_body = par_response.text

    if (
        par_response.status_code not in [200, 201]
        or not isinstance(par_body, dict)
        or "request_uri" not in par_body
    ):
        return {
            "error": "PAR request failed",
            "par_status_code": par_response.status_code,
            "par_response": par_body,
            "client_id": client_id,
            "redirect_uri_sent": REDIRECT_URI,
            "par_endpoint": PAR_ENDPOINT,
        }, 400

    request_uri = par_body["request_uri"]

    params = {
        "client_id": client_id,
        "request_uri": request_uri,
        "redirect_uri": REDIRECT_URI,
    }

    auth_url = AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route("/login-with-client-secret")
def login_with_client_secret():
    # Create a dedicated DCR client authenticated with client_secret_basic.
    metadata = build_client_registration_metadata()
    metadata["client_name"] = metadata.get("client_name", "FAPI MCP DCR Client") + " (client_secret)"
    metadata["token_endpoint_auth_method"] = "client_secret_basic"
    metadata.pop("jwks", None)
    metadata.pop("token_endpoint_auth_signing_alg", None)

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if DCR_INITIAL_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {DCR_INITIAL_ACCESS_TOKEN}"

    dcr_response = requests.post(
        DCR_ENDPOINT,
        headers=headers,
        json=metadata,
        timeout=15,
    )

    body = dcr_response.json()
    if dcr_response.status_code not in [200, 201]:
        return {"error":"dynamic_client_registration_failed","response":body},400

    client_id = body["client_id"]
    client_secret = body.get("client_secret")

    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    client_session_id = secrets.token_urlsafe(32)

    session["code_verifier"] = code_verifier
    session["state"] = state
    session["nonce"] = nonce
    session["client_session_id"] = client_session_id
    session["client_id"] = client_id
    session["client_secret"] = client_secret
    session["client_auth_method"] = "client_secret_basic"

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    return redirect(AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params))


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return {
            "error": request.args.get("error"),
            "error_description": request.args.get("error_description"),
        }, 400

    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return {"error": "authorization code not found"}, 400

    if state != session.get("state"):
        return {
            "error": "invalid state",
            "returned_state": state,
            "session_state": session.get("state"),
        }, 400

    code_verifier = session.get("code_verifier")
    client_id = session.get("client_id") or current_client_id()

    token_dpop_proof = create_dpop_proof("POST", TOKEN_ENDPOINT)

    if session.get("client_auth_method") == "client_secret_basic":
        response = requests.post(
            TOKEN_ENDPOINT,
            headers={"DPoP": token_dpop_proof},
            auth=(client_id, session.get("client_secret")),
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier,
            },
            timeout=10,
        )
    else:
        client_assertion = create_client_assertion(ISSUER, client_id=client_id)
        response = requests.post(
            TOKEN_ENDPOINT,
            headers={"DPoP": token_dpop_proof},
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": client_assertion,
            },
            timeout=10,
        )

    try:
        body = response.json()
    except Exception:
        body = response.text

    if isinstance(body, dict) and "access_token" in body:
        access_token = body["access_token"]
        client_session_id = session.get("client_session_id")

        if not client_session_id:
            return {"error": "client_session_id not found"}, 400

        # Store the token server-side. The next screen only displays the token;
        # MCP server access is executed later when the user clicks the button.
        TOKEN_STORE[client_session_id] = {
            "access_token": access_token,
            "token_response": body,
            "client_id": client_id,
        }

        registered_client_summary = {
            "client_id": client_id,
            "token_endpoint_auth_method": session.get(
                "client_auth_method",
                "private_key_jwt",
            ),
        }

        registered_client_json = html.escape(
            json.dumps(registered_client_summary, indent=2, ensure_ascii=False)
        )
        token_response_json = html.escape(
            json.dumps(body, indent=2, ensure_ascii=False)
        )

        return f"""
        <h1>Token acquired successfully</h1>

        <p>
            Dynamic Client Registration and OAuth token acquisition are complete.
            The MCP server has not been called yet.
        </p>

        <h2>Registered client information</h2>
        <pre>{registered_client_json}</pre>

        <h2>Token Endpoint result</h2>
        <pre>{token_response_json}</pre>

        <form action="/call-resource" method="post">
            <button type="submit">
                Access MCP Server with this access token
            </button>
        </form>

        <p><a href="/">Back to top</a></p>
        """

    return {
        "token_endpoint_status_code": response.status_code,
        "token_response": body,
        "client_id": client_id,
    }, response.status_code


@app.route("/call-resource", methods=["POST"])
def call_resource():
    client_session_id = session.get("client_session_id")

    if not client_session_id:
        return {"error": "client_session_id not found"}, 400

    stored = TOKEN_STORE.get(client_session_id)
    if not stored:
        return {
            "error": "access token not found",
            "detail": "Please login again from /login",
        }, 400

    resource_response = call_resource_server(stored["access_token"])

    return {
        "message": "MCP Server access executed",
        "resource_server_response": resource_response,
    }


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=3000,
        debug=True,
        ssl_context="adhoc",
    )
