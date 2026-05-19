import logging
from contextlib import asynccontextmanager
import jwt
from jwt import PyJWKClient

from starlette.applications import Starlette

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
from starlette.responses import JSONResponse, Response
from starlette.routing import Route, Mount
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

from mcp.server.fastmcp import FastMCP


# =============================================================================
# 設定
# =============================================================================

KEYCLOAK_BASE = "http://localhost:8080"
REALM         = "myrealm"

# Keycloak の issuer (トークン検証の iss クレームと照合)
ISSUER   = f"{KEYCLOAK_BASE}/realms/{REALM}"

# JWK Set エンドポイント (公開鍵取得用)
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"

MCP_SERVER_BASE = "http://localhost:3000"
MCP_RESOURCE = f"{MCP_SERVER_BASE}/mcp"

PRM_URL = f"{MCP_SERVER_BASE}/.well-known/oauth-protected-resource"

# アクセストークンに要求するスコープ
REQUIRED_SCOPE = "mcp"

# =============================================================================
# FastMCP サーバ定義
# =============================================================================

mcp = FastMCP("Hello MCP Server", host="localhost", port=3000)


@mcp.tool()
def hello() -> str:
    """Helloと出力するだけのツール"""
    return "Hello"


# =============================================================================
# トークン検証
# =============================================================================

_jwks_client = PyJWKClient(JWKS_URI)


def _extract_scopes(claims: dict) -> set[str]:
    """Keycloak が "scope" クレームにスペース区切りで格納したスコープを集合で返す"""
    return set((claims.get("scope") or "").split())


def verify_bearer_token(token: str) -> dict:
    """
    Bearer トークンを検証して claims を返す。
    検証項目:
      - 署名 (JWKS による RS256)
      - 有効期限 (exp)
      - 発行者 (iss == ISSUER)
      - オーディエンス (aud が存在する場合は MCP_RESOURCE と照合)
    """
    key = _jwks_client.get_signing_key_from_jwt(token).key

    # aud クレームの有無を事前確認
    # Keycloak の RFC 8707 resource パラメータ対応状況に応じて aud なしのトークンも存在する
    unverified = jwt.decode(token, options={"verify_signature": False})
    has_aud    = "aud" in unverified

    claims = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=MCP_RESOURCE if has_aud else None,
        options={"verify_aud": has_aud},
    )
    # scope クレームの内容をデバッグ出力して認可フローでスコープが割り当てられるかを確認する
    logger.debug(
        "JWT デコード成功: sub=%s | scopeクレーム=%r | 全クレームキー=%s",
        claims.get("sub"), claims.get("scope"), list(claims.keys())
    )
    return claims


# =============================================================================
# CORS ヘルパー
# =============================================================================

def _cors_headers(origin: str | None) -> dict:
    return {
        "Access-Control-Allow-Origin":   origin or "*",
        "Access-Control-Allow-Methods":  "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers":  "authorization, content-type, mcp-session-id",
        "Access-Control-Expose-Headers": "mcp-session-id",
        "Access-Control-Max-Age":        "86400",
    }


# =============================================================================
# Bearer 認証ミドルウェア
# =============================================================================

class BearerAuthMiddleware(BaseHTTPMiddleware):
    """
    /mcp パスへのリクエストに Bearer トークン認証を要求する。

    MCP 仕様の要件:
      - トークン未提示: 401 + WWW-Authenticate: Bearer resource_metadata="<PRM_URL>"
      - スコープ不足:  403 + WWW-Authenticate: Bearer error="insufficient_scope"
      - トークン不正:  401 + WWW-Authenticate: Bearer error="invalid_token"
      - CORS preflight (OPTIONS): 認証不要でそのまま通す
    """

    async def dispatch(self, request, call_next):
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        # CORS preflight は認証不要
        if request.method == "OPTIONS":
            return await call_next(request)

        authz = request.headers.get("authorization", "")
        if not authz.lower().startswith("bearer "):
            # MCP spec: 401 + resource_metadata でクライアントに PRM の場所を伝える
            return Response(
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{PRM_URL}", '
                        f'scope="{REQUIRED_SCOPE}"'
                    )
                },
            )

        token = authz.split(" ", 1)[1].strip()
        try:
            claims = verify_bearer_token(token)
        except Exception:
            return Response(
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="invalid_token", '
                        f'resource_metadata="{PRM_URL}"'
                    )
                },
            )

        if REQUIRED_SCOPE not in _extract_scopes(claims):
            return Response(
                status_code=403,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="insufficient_scope", '
                        f'scope="{REQUIRED_SCOPE}", '
                        f'resource_metadata="{PRM_URL}"'
                    )
                },
            )

        # 検証済み claims をリクエストステートに格納 (ツール内で参照可能)
        request.state.claims = claims
        return await call_next(request)


# =============================================================================
# Protected Resource Metadata エンドポイント (RFC 9728)
#
# MCP 仕様:
#   - /.well-known/oauth-protected-resource を公開する必要がある
#   - resource: このサーバの識別子
#   - authorization_servers: 認可サーバ (Keycloak) の issuer URL のリスト
#   - scopes_supported: サポートするスコープのリスト
# =============================================================================

async def prm_get(request):
    origin = request.headers.get("origin")
    return JSONResponse(
        {
            "resource":              MCP_RESOURCE,
            "authorization_servers": [ISSUER],
            "scopes_supported":      [REQUIRED_SCOPE],
        },
        headers=_cors_headers(origin),
    )


async def prm_options(request):
    origin = request.headers.get("origin")
    return Response(status_code=204, headers=_cors_headers(origin))


# =============================================================================
# RFC 8414 Authorization Server Metadata エンドポイント
#
# /.well-known/oauth-authorization-server  : RFC 8414
# /.well-known/openid-configuration        : OpenID Connect Discovery 1.0
# =============================================================================

def _as_metadata_payload() -> dict:
    """Keycloak の各エンドポイントを指す RFC 8414 準拠の AS メタデータ"""
    base = f"{ISSUER}/protocol/openid-connect"
    return {
        "issuer":                                ISSUER,
        "authorization_endpoint":                f"{base}/auth",
        "token_endpoint":                        f"{base}/token",
        "jwks_uri":                              JWKS_URI,
        "registration_endpoint":                 f"{ISSUER}/clients-registrations/openid-connect",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported":      ["S256"],
        "scopes_supported":                      ["openid", REQUIRED_SCOPE],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
    }


async def as_metadata_get(request):
    origin = request.headers.get("origin")
    return JSONResponse(_as_metadata_payload(), headers=_cors_headers(origin))


async def as_metadata_options(request):
    origin = request.headers.get("origin")
    return Response(status_code=204, headers=_cors_headers(origin))


# Mount 配下では FastMCP サブアプリの lifespan が自動で走らないため、
# 親アプリで session manager の run() を明示的に起動する。
@asynccontextmanager
async def lifespan(app):
    _ = app
    async with mcp.session_manager.run():
        yield


# =============================================================================
# Starlette アプリ組み立て
# =============================================================================

app = Starlette(
    lifespan=lifespan,
    routes=[
        # RFC 9728 Protected Resource Metadata (ルートパス & /mcp パス付き の両方を公開)
        Route("/.well-known/oauth-protected-resource",      prm_get,     methods=["GET"]),
        Route("/.well-known/oauth-protected-resource",      prm_options, methods=["OPTIONS"]),
        Route("/.well-known/oauth-protected-resource/mcp",  prm_get,     methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp",  prm_options, methods=["OPTIONS"]),

        # MCP Streamable HTTP (Bearer 認証ミドルウェアを適用)
        Mount("/", app=mcp.streamable_http_app(), middleware=[Middleware(BearerAuthMiddleware)]),
    ]
)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
