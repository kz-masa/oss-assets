import asyncio
import base64
import hashlib
import logging
import secrets
import sys
import urllib.parse
import webbrowser
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
import uvicorn
from urllib.parse import urlparse, urlunparse

MCP_SERVER_URL = "http://localhost:3000/mcp"
CLIENT_ID_URL = "http://localhost:8081/oauth/metadata.json"
REDIRECT_URI = "http://localhost:8081/callback"

discovered_endpoints = {
    "auth_endpoint": None,
    "token_endpoint": None
}

code_queue = asyncio.Queue()
stop_event = asyncio.Event()

pkce_verifier = ""

redirect_app = FastAPI()


@redirect_app.get("/oauth/metadata.json")
async def get_cimd_document():
    print("\n=== FLOW (5): client server metadata ===")
    metadata = {
        "client_id": CLIENT_ID_URL,
        "client_name": "MCP Client",
        "client_uri": "http://localhost:8081",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    }
    return JSONResponse(content=metadata)


@redirect_app.get("/callback")
async def auth_callback(request: Request):
    code = request.query_params.get("code")
    if code:
        await code_queue.put(code)
        return HTMLResponse(
            content="""
            <html>
                <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                    <h2 style="color: #2e7d32;">Authentication Success</h2>
                    <p>please, close this tab and back to console.</p>
                </body>
            </html>
        """
        )
    return HTMLResponse(content="<h2>Authentication error</h2>", status_code=400)


async def start_redirect_server():
    config = uvicorn.Config(redirect_app, host="127.0.0.1", port=8081, log_level="warning")
    server = uvicorn.Server(config)

    async def serve_with_shutdown():
        await server.serve()

    server_task = asyncio.create_task(serve_with_shutdown())
    await stop_event.wait()
    server.should_exit = True
    await server_task


async def discover_oauth_endpoints():
    print("\n=== FLOW (1): MCP request without access token ===")
    async with httpx.AsyncClient() as client:
        # 1. request without access token
        print(f"MCP Server URL: {MCP_SERVER_URL}")
        resp = await client.get(MCP_SERVER_URL)
        
        if resp.status_code != 401:
            raise RuntimeError(f"Expected 401 Unauthorized, but got {resp.status_code}")
        
        # 2. get resource_metadata url
        www_auth = resp.headers.get("WWW-Authenticate", "")
        print(f"Received WWW-Authenticate: {www_auth}")

        if 'resource_metadata="' not in www_auth:
            raise RuntimeError("resource_metadata not found in WWW-Authenticate header")
        
        metadata_url = www_auth.split('resource_metadata="')[1].split('"')[0]

        # 3. request MCP resource server metadata
        print("\n=== FLOW (2): resource server metadata ===")
        meta_resp = await client.get(metadata_url)
        meta_resp.raise_for_status()
        resource_metadata = meta_resp.json()
        
        auth_servers = resource_metadata.get("authorization_servers", [])
        if not auth_servers:
            raise RuntimeError("No authorization servers listed in resource metadata")
        
        issuer_url = auth_servers[0]
        print(f"Discovered Authorization Server Issuer: {issuer_url}")
        
        # 4. request MCP authorization server metadata
        print("\n=== FLOW (3): authorization server metadata ===")
        well_known_url = create_well_known_url(issuer_url)
        print(f"Well Known URL: {well_known_url}")
        oidc_resp = await client.get(well_known_url)
        oidc_resp.raise_for_status()
        oidc_config = oidc_resp.json()
        
        # 5. get MCP authorization server endpoints
        discovered_endpoints["auth_endpoint"] = oidc_config.get("authorization_endpoint")
        discovered_endpoints["token_endpoint"] = oidc_config.get("token_endpoint")
        
        print(f"Authorization Endpoint: {discovered_endpoints['auth_endpoint']}")
        print(f"Token Endpoint:         {discovered_endpoints['token_endpoint']}")

def create_well_known_url(issuer: str) -> str:
    parsed = urlparse(issuer)
    prefix = "/.well-known/oauth-authorization-server"
    if parsed.path:
        new_path = prefix + parsed.path
    else:
        new_path = prefix
    updated_parsed = parsed._replace(path=new_path)
    return urlunparse(updated_parsed)

def generate_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=') 
    return verifier, challenge

async def get_token_via_cimd(custom_scope: str) -> str:
    global pkce_verifier

    asyncio.create_task(start_redirect_server())
    await asyncio.sleep(1)

    auth_endpoint = discovered_endpoints["auth_endpoint"]
    token_endpoint = discovered_endpoints["token_endpoint"]

    full_scope = f"openid petshop-roles {custom_scope}".strip()

    pkce_verifier, code_challenge = generate_pkce_pair()

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID_URL,
        "redirect_uri": REDIRECT_URI,
        "scope": full_scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

    print("\n=== FLOW (4): authorization request ===")
    print("Open your browser. If your browser doesn't open, please manually access the following URL:")
    print(f"{auth_url}")

    webbrowser.open(auth_url)

    auth_code = await code_queue.get()
    print("\n=== FLOW (10): authorization response ===")
    print(f"Authorization Code: {auth_code}")

    print("\n=== STEP (11): token request ===")
    async with httpx.AsyncClient() as client:
        data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID_URL,
            "code_verifier": pkce_verifier
        }
        response = await client.post(token_endpoint, data=data)
        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get("access_token")
        print(f"Access Token: {access_token}")

        stop_event.set()
        await asyncio.sleep(0.5)
        return access_token

async def call_mcp(token: str, tool_name: str):
    print("\n=== FLOW (12)-(15): MCP request with access token ===")

    client = Client(
        MCP_SERVER_URL,
        auth=BearerAuth(token)
    )
    try:
        async with client:
            # get tools/list
            result_obj = await client.list_tools()

            print("--- Available MCP Tools ---")
            available_tool_names = set()
            for tool in result_obj:
                print(f"- {tool.name}: {tool.description}")
                available_tool_names.add(tool.name)

            if tool_name not in available_tool_names:
                print("\n==============================================")
                print(f"Requested tool '{tool_name}' is not available.")
                print("Execution stopped to prevent unauthorized call_tool.")
                print("==============================================")
                return

            print(f"\nRun tool: [{tool_name}] ...")
            match tool_name:
                case "user_create_user":
                    arguments = {"body": {"id": 4, "name": "jiro tanaka", "email": "tanaka@example.com"}}
                case "user_get_user":
                    arguments = {"path": {"user_id": 1}}
                case "pet_create_pet":
                    arguments = {"body": {"id": 2, "type": "cat", "name": "tama"}}
                case "pet_get_pet":
                    arguments = {"path": {"pet_id": 1}}
                case _:
                    arguments = {}

            result = await client.call_tool(tool_name, arguments)

            print("\n================================")
            print("===        MCP RESULT        ===")
            print("================================")
            for content in result.content:
                if content.type == "text":
                    print(content.text)
            print("================================")
    except httpx.HTTPStatusError as e:
        print("\n===============================")
        print("===    HTTP STATUS ERROR    ===")
        print("===============================")
        print(f"Status Code: {e.response.status_code}")
        print(f"Error Body : {e.response.text}")
        print("===============================")
        return
    except Exception as e:
        if hasattr(e, "response") and e.response is not None:
            print("\n===============================")
            print("===    HTTP STATUS ERROR    ===")
            print("===============================")
            print(f"Status Code: {e.response.status_code}")
            print(f"Error Body : {e.response.text}")
            print("===============================")
            return
        raise e

def parse_arguments() -> tuple[str, str] | None:
    DEFAULT_TOOL = "user_create_user"
    DEFAULT_SCOPE = ""

    match sys.argv:
        case [_]:
            target_tool = DEFAULT_TOOL
            target_scope = DEFAULT_SCOPE
            print(f"No arguments provided. Running default: tool=[{target_tool}], scope=[{target_scope}]")
            return target_tool, target_scope
        case [_, tool]:
            target_tool = tool
            target_scope = DEFAULT_SCOPE
            print(f"Scope omitted. Automatically inferred: tool=[{target_tool}], scope=[{target_scope}]")
            return target_tool, target_scope
        case [_, tool, scope]:
            target_tool = tool
            target_scope = scope
            print(f"Running with specified arguments: tool=[{target_tool}], scope=[{target_scope}]")
            return target_tool, target_scope
        case _:
            print("Too many arguments.")
            print("Usage: python filename.py <tool_name> <scope>")
            print("Example: python filename.py pet_create_pet create\n")
            return None

async def main():
    parsed_args = parse_arguments()
    if parsed_args is None:
        return

    target_tool, target_scope = parsed_args

    try:
        await discover_oauth_endpoints()
 
        token = await get_token_via_cimd(target_scope)
        await call_mcp(token, target_tool)
    except Exception as e:
        print(f"\n[FATAL ERROR] System execution failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
