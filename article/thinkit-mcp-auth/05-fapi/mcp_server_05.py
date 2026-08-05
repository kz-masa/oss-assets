import base64
import hashlib
import json
import os
import time
from urllib.parse import urlparse, urlunparse

import jwt
import requests
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request

load_dotenv()

# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP(
    name="DPoP Protected MCP Server"
)

# ============================================================
# 設定値
# ============================================================

KEYCLOAK_BASE_URL = os.getenv(
    "KEYCLOAK_BASE_URL",
    "http://localhost:8080"
)

REALM = os.getenv(
    "REALM",
    "mcp-fapi2"
)

ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{REALM}"

JWKS_URL = (
    f"{ISSUER}/protocol/openid-connect/certs"
)

# MCP HTTP endpoint
# DPoP proof の htu と照合する
MCP_RESOURCE_URL = os.getenv(
    "MCP_RESOURCE_URL",
    "http://localhost:9000/mcp"
)

EXPECTED_AUDIENCE = os.getenv(
    "EXPECTED_AUDIENCE",
    ""
)

DPOP_IAT_LEEWAY_SECONDS = int(
    os.getenv("DPOP_IAT_LEEWAY_SECONDS", "300")
)

# ハンズオン用の簡易 jti ストア
# 本番では Redis 等を使う
USED_DPOP_JTI = {}


# ============================================================
# 共通ユーティリティ
# ============================================================

def base64url_encode(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(data)
        .rstrip(b"=")
        .decode("ascii")
    )


def normalize_htu(url: str) -> str:
    """
    DPoP htu 比較用にURLを正規化する。
    query / fragment は比較対象から外す。
    """
    parsed = urlparse(url)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "",
        "",
        ""
    ))


def create_ath(access_token: str) -> str:
    """
    ath = base64url( SHA-256(access_token) )
    """
    digest = hashlib.sha256(
        access_token.encode("ascii")
    ).digest()

    return base64url_encode(digest)


def jwk_thumbprint(jwk: dict) -> str:
    """
    RFC7638 に沿って EC JWK の thumbprint を計算する。
    今回は DPoP 用の P-256 鍵を前提にする。
    """
    if jwk.get("kty") != "EC":
        raise ValueError("Only EC JWK is supported in this demo")

    thumbprint_json = json.dumps(
        {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        thumbprint_json.encode("utf-8")
    ).digest()

    return base64url_encode(digest)


def cleanup_used_jti():
    now = int(time.time())

    expired = [
        jti for jti, exp in USED_DPOP_JTI.items()
        if exp < now
    ]

    for jti in expired:
        del USED_DPOP_JTI[jti]


# ============================================================
# Access Token 検証
# ============================================================

def get_keycloak_signing_key(access_token: str):
    """
    Access Token の kid をもとに、
    Keycloak JWKS から署名検証用公開鍵を取得する。
    """
    jwks = requests.get(
        JWKS_URL,
        timeout=10
    ).json()

    token_header = jwt.get_unverified_header(
        access_token
    )

    kid = token_header.get("kid")

    if not kid:
        raise ValueError("Access token header does not contain kid")

    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )

    raise ValueError(f"Signing key not found for kid={kid}")


def verify_access_token(access_token: str) -> dict:
    """
    Keycloak が発行した DPoP-bound Access Token を検証する。

    検証内容:
      - JWT署名
      - exp
      - iss
      - aud (本ハンズオンでは簡単のため割愛)
      - cnf.jkt の存在
    """
    signing_key = get_keycloak_signing_key(access_token)

    token_header = jwt.get_unverified_header(access_token)
    print("Access Token header:", token_header)

    decode_options = {
        "verify_aud": bool(EXPECTED_AUDIENCE)
    }

    decode_args = {
        "jwt": access_token,
        "key": signing_key,

        # FAPI profile適用後、KeycloakのAccess Token署名がPS256になる場合がある
        "algorithms": ["RS256", "PS256"],

        "issuer": ISSUER,
        "options": decode_options,
    }

    if EXPECTED_AUDIENCE:
        decode_args["audience"] = EXPECTED_AUDIENCE

    claims = jwt.decode(**decode_args)

    cnf = claims.get("cnf")

    if not cnf or not cnf.get("jkt"):
        raise ValueError("Access token does not contain cnf.jkt")

    return claims


# ============================================================
# DPoP proof 検証
# ============================================================

def verify_dpop_proof(
    dpop_proof: str,
    access_token: str,
    access_token_claims: dict,
    expected_method: str,
    expected_url: str,
) -> dict:
    """
    DPoP proof JWT を検証する。

    検証内容:
      1. typ = dpop+jwt
      2. alg = ES256
      3. header.jwk の存在
      4. DPoP proof の署名検証
      5. htm 検証
      6. htu 検証
      7. iat 検証
      8. jti 再利用防止
      9. ath 検証
      10. cnf.jkt 検証
    """
    dpop_header = jwt.get_unverified_header(
        dpop_proof
    )

    if dpop_header.get("typ") != "dpop+jwt":
        raise ValueError("Invalid DPoP typ")

    if dpop_header.get("alg") != "ES256":
        raise ValueError("Invalid DPoP alg")

    dpop_jwk = dpop_header.get("jwk")

    if not dpop_jwk:
        raise ValueError("DPoP proof header does not contain jwk")

    dpop_public_key = jwt.algorithms.ECAlgorithm.from_jwk(
        json.dumps(dpop_jwk)
    )

    proof_claims = jwt.decode(
        dpop_proof,
        dpop_public_key,
        algorithms=["ES256"],
        options={
            "verify_aud": False
        }
    )

    # htm
    actual_htm = proof_claims.get("htm")

    if actual_htm != expected_method.upper():
        raise ValueError(
            f"Invalid htm: expected={expected_method.upper()}, actual={actual_htm}"
        )

    # htu
    actual_htu = normalize_htu(
        proof_claims.get("htu", "")
    )

    expected_htu = normalize_htu(
        expected_url
    )

    if actual_htu != expected_htu:
        raise ValueError(
            f"Invalid htu: expected={expected_htu}, actual={actual_htu}"
        )

    # iat
    now = int(time.time())
    iat = proof_claims.get("iat")

    if not isinstance(iat, int):
        raise ValueError("DPoP proof does not contain valid iat")

    if abs(now - iat) > DPOP_IAT_LEEWAY_SECONDS:
        raise ValueError("DPoP proof iat is outside allowed time window")

    # jti replay check
    cleanup_used_jti()

    jti = proof_claims.get("jti")

    if not jti:
        raise ValueError("DPoP proof does not contain jti")

    if jti in USED_DPOP_JTI:
        raise ValueError("DPoP proof jti has already been used")

    USED_DPOP_JTI[jti] = now + DPOP_IAT_LEEWAY_SECONDS

    # ath
    expected_ath = create_ath(access_token)
    actual_ath = proof_claims.get("ath")

    if actual_ath != expected_ath:
        raise ValueError("Invalid ath")

    # cnf.jkt
    access_token_jkt = access_token_claims["cnf"]["jkt"]
    dpop_jkt = jwk_thumbprint(dpop_jwk)

    if access_token_jkt != dpop_jkt:
        raise ValueError("cnf.jkt does not match DPoP public key thumbprint")

    return proof_claims


# ============================================================
# MCP Tool実行時の認可チェック
# ============================================================

def verify_current_mcp_request() -> dict:
    """
    現在のMCP HTTPリクエストから
    Authorization / DPoP ヘッダーを取り出して検証する。
    """
    request = get_http_request()

    authorization = request.headers.get("Authorization")
    dpop_proof = request.headers.get("DPoP")

    if not authorization:
        raise PermissionError("missing_authorization_header")

    if not authorization.startswith("DPoP "):
        raise PermissionError("invalid_authorization_scheme")

    access_token = authorization.removeprefix("DPoP ").strip()

    if not access_token:
        raise PermissionError("missing_access_token")

    if not dpop_proof:
        raise PermissionError("missing_dpop_header")

    access_token_claims = verify_access_token(
        access_token
    )

    dpop_claims = verify_dpop_proof(
        dpop_proof=dpop_proof,
        access_token=access_token,
        access_token_claims=access_token_claims,
        expected_method=request.method,
        expected_url=MCP_RESOURCE_URL,
    )

    return {
        "access_token_claims": access_token_claims,
        "dpop_claims": dpop_claims,
    }


# ============================================================
# MCP Tools
# ============================================================

@mcp.tool
def protected_echo(message: str) -> dict:
    """
    DPoP-bound Access Token が有効な場合だけ実行できるMCP Tool。

    引数:
      message: クライアントから送られたメッセージ

    戻り値:
      DPoP検証結果と echo メッセージ
    """
    verification = verify_current_mcp_request()

    access_token_claims = verification["access_token_claims"]
    dpop_claims = verification["dpop_claims"]

    return {
        "message": "DPoP-protected MCP tool call succeeded",
        "echo": message,
        "access_token_subject": access_token_claims.get("sub"),
        "access_token_client": access_token_claims.get("azp"),
        "access_token_cnf": access_token_claims.get("cnf"),
        "dpop_htm": dpop_claims.get("htm"),
        "dpop_htu": dpop_claims.get("htu"),
        "dpop_jti": dpop_claims.get("jti"),
    }


# ============================================================
# 起動
# ============================================================

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=9000,
    )