import os
import time
import secrets
import requests
import anyio
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic_settings import BaseSettings
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


class Settings(BaseSettings):
    KC_BASE_URL_MAIN: str
    KC_REALM_MAIN: str
    KC_BASE_URL_SECOND: str
    KC_REALM_SECOND: str
    KC_CLIENT_ID: str
    KC_CLIENT_SECRET: str
    BACKEND_REDIRECT_URI: str
    FRONTEND_AFTER_LOGIN: str
    FRONTEND_AFTER_LOGOUT: str
    STATE_SECRET: str
    COOKIE_NAME: str = "sid"
    # COOKIE_SAMESITE: str = "lax"
    COOKIE_SAMESITE: str = "none"
    COOKIE_SECURE: bool = True
    # COOKIE_SECURE: bool = False
    SSO_USERNAME: str
    SSO_PASSWORD: str
    OIDC_CONFIG_TTL_SECONDS: int = 3600
    STATE_MAX_AGE_SECONDS: int = 600
    ALLOWED_ORIGINS: list

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
app = FastAPI(title="Keycloak BFF Auth")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


state_ser = URLSafeTimedSerializer(settings.STATE_SECRET, salt="oidc-state")

SESSIONS: Dict[str, Dict[str, Any]] = {}

_oidc_cache: Dict[str, Any] = {"data": None, "exp": 0.0}


async def get_oidc_config() -> Dict[str, Any]:
    now = time.time()
    if _oidc_cache["data"] and now < _oidc_cache["exp"]:
        return _oidc_cache["data"]

    def _fetch():
        url = f"{settings.KC_BASE_URL_MAIN}/realms/{settings.KC_REALM_MAIN}/.well-known/openid-configuration"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()

    data = await anyio.to_thread.run_sync(_fetch)

    _oidc_cache["data"] = data
    _oidc_cache["exp"] = now + settings.OIDC_CONFIG_TTL_SECONDS
    return data


def _decode_jwt_no_verify(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}


async def _refresh_tokens_if_needed(session: Dict[str, Any]) -> None:
    tokens = session.get("tokens", {})
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not access_token or not refresh_token:
        return

    payload = _decode_jwt_no_verify(access_token)
    exp = int(payload.get("exp", 0))
    now = int(time.time())

    if exp and exp - now > 60:
        return

    oidc = await get_oidc_config()
    token_endpoint = oidc["token_endpoint"]

    form = {
        "grant_type": "refresh_token",
        "client_id": settings.KC_CLIENT_ID,
        "client_secret": settings.KC_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(token_endpoint, data=form)
        if r.status_code >= 400:
            raise HTTPException(status_code=401, detail="Session expired")
        new_tokens = r.json()

    if "refresh_token" not in new_tokens:
        new_tokens["refresh_token"] = refresh_token

    session["tokens"] = new_tokens
    session["updated_at"] = time.time()


async def require_session(request: Request) -> Dict[str, Any]:
    # sid = request.cookies.get(settings.COOKIE_NAME)
    # if not sid or sid not in SESSIONS:
    #     raise HTTPException(status_code=401)
    sid = request.query_params.get("sid")
    if not sid:
        raise HTTPException(status_code=401, detail="no_session")
    session = SESSIONS[sid]
    try:
        await _refresh_tokens_if_needed(session)
    except HTTPException:
        SESSIONS.pop(sid, None)
        raise
    return session

async def _model_token_expired(model_tokens: dict) -> bool:
    exp = model_tokens.get("expires_at")
    if not exp:
        return True
    return time.time() >= exp - 30

async def _normalize_model_tokens(tokens: dict) -> dict:
    expires_in = tokens.get("expires_in", 0)
    tokens["expires_at"] = time.time() + expires_in
    return tokens

async def _refresh_model_tokens() -> dict:
    token_url = f"{settings.KC_BASE_URL_SECOND}/realms/{settings.KC_REALM_SECOND}/protocol/openid-connect/token"

    token_data = {
        "grant_type": "password",
        "client_id": "end-users",
        "username": settings.SSO_USERNAME,
        "password": settings.SSO_PASSWORD,
    }

    r = requests.post(
        token_url,
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )

    if r.status_code != 200:
        raise HTTPException(status_code=502, detail="model_token_refresh_failed")

    return await _normalize_model_tokens(r.json())


@app.get("/auth/login")
async def auth_login(request: Request, kc_idp_hint: Optional[str] = None, force: bool = False):
    sid = request.cookies.get(settings.COOKIE_NAME)
    if sid and sid in SESSIONS and not force:
        return RedirectResponse(settings.FRONTEND_AFTER_LOGIN)

    oidc = await get_oidc_config()

    nonce = secrets.token_urlsafe(16)
    state_data = {"r": secrets.token_urlsafe(16), "nonce": nonce}
    state = state_ser.dumps(state_data)

    params = {
        "client_id": settings.KC_CLIENT_ID,
        "redirect_uri": settings.BACKEND_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "nonce": nonce
    }

    if kc_idp_hint:
        params["kc_idp_hint"] = kc_idp_hint
    if force:
        params["prompt"] = "login"

    url = str(httpx.URL(oidc["authorization_endpoint"]).copy_merge_params(params))
    return RedirectResponse(url)


@app.get("/auth/callback")
async def auth_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    if error:
        return JSONResponse(
            {
                "error": error,
                "error_description": request.query_params.get("error_description")
            },
            status_code=400,
        )

    if not code or not state:
        return JSONResponse({"error": "missing_code_or_state"}, status_code=400)

    try:
        state_data = state_ser.loads(state, max_age=settings.STATE_MAX_AGE_SECONDS)
        expected_nonce = state_data.get("nonce")
    except (BadSignature, SignatureExpired):
        return JSONResponse({"error": "bad_state"}, status_code=400)

    if not expected_nonce:
        return JSONResponse({"error": "missing_nonce"}, status_code=400)

    oidc = await get_oidc_config()

    form = {
        "grant_type": "authorization_code",
        "client_id": settings.KC_CLIENT_ID,
        "client_secret": settings.KC_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.BACKEND_REDIRECT_URI,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        tr = await client.post(oidc["token_endpoint"], data=form)
        if tr.status_code >= 400:
            return JSONResponse(
                {"error": "token_exchange_failed", "details": tr.text},
                status_code=400,
            )
        tokens = tr.json()

    jwk_client = jwt.PyJWKClient(oidc["jwks_uri"])
    try:
        signing_key = jwk_client.get_signing_key_from_jwt(tokens["id_token"]).key
        user = jwt.decode(
            tokens["id_token"],
            signing_key,
            algorithms=["RS256"],
            audience=settings.KC_CLIENT_ID,
            issuer=oidc["issuer"],
        )
    except Exception:
        return JSONResponse({"error": "invalid_id_token"}, status_code=400)

    email = user.get("email")
    if not email:
        return JSONResponse(
            {"error": "email_missing_in_id_token"},
            status_code=400,
        )

    token_nonce = user.get("nonce")
    if token_nonce != expected_nonce:
        return JSONResponse({"error": "bad_nonce"}, status_code=400)

    token_url = f"{settings.KC_BASE_URL_SECOND}/realms/{settings.KC_REALM_SECOND}/protocol/openid-connect/token"
    token_data = {
        "grant_type": "password",
        "client_id": "end-users",
        "username": settings.SSO_USERNAME,
        "password": settings.SSO_PASSWORD,
    }

    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(token_url, data=token_data, headers=token_headers)
    if response.status_code != 200:
        model_tokens = {"error": response.text}
    else:
        model_tokens = response.json()

    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {
        "tokens": tokens,
        "user": user,
        "created_at": time.time(),
        "updated_at": time.time(),
        "model_tokens": await _normalize_model_tokens(model_tokens)
    }

    redirect_url = (
        f"{settings.FRONTEND_AFTER_LOGIN}"
        f"?sid={sid}"
    )

    resp = RedirectResponse(redirect_url)
    resp.set_cookie(
        settings.COOKIE_NAME,
        sid,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )
    return resp

@app.get("/api/me")
async def api_me(session: Dict[str, Any] = Depends(require_session)):
    return {
        "user": session["user"],
        "session_created_at": session["created_at"],
        "model_tokens": session["model_tokens"]
    }

@app.get("/get_model_tokens")
async def get_model_tokens(request: Request):

    # sid = request.cookies.get(settings.COOKIE_NAME)
    # if not sid:
    #     raise HTTPException(status_code=401, detail="no_session")
    sid = request.query_params.get("sid")
    if not sid:
        raise HTTPException(status_code=401, detail="no_session")

    session = SESSIONS.get(sid)
    if not session:
        raise HTTPException(status_code=401, detail="invalid_session")

    await _refresh_tokens_if_needed(session)

    model_tokens = session.get("model_tokens")
    if not model_tokens or await _model_token_expired(model_tokens):
        session["model_tokens"] = await _refresh_model_tokens()
        session["updated_at"] = time.time()

    return {
        "user": session["user"],
        "session_created_at": session["created_at"],
        "model_tokens": session["model_tokens"],
    }

@app.get("/auth/logout")
async def auth_logout(request: Request):
    sid = request.cookies.get(settings.COOKIE_NAME)

    session = SESSIONS.get(sid)
    id_token_hint = (
        session.get("tokens", {}).get("id_token")
        if session else None
    )

    if sid:
        SESSIONS.pop(sid, None)

    oidc = await get_oidc_config()
    # end_session = oidc.get("end_session_endpoint") or (
    #     f"{settings.KC_REALM_MAIN}/protocol/openid-connect/logout"
    # )
    end_session = oidc["end_session_endpoint"]

    params = {
        "post_logout_redirect_uri": settings.FRONTEND_AFTER_LOGOUT,
        "client_id": settings.KC_CLIENT_ID,
    }

    if id_token_hint:
        params["id_token_hint"] = id_token_hint

    resp = RedirectResponse(
        str(httpx.URL(end_session).copy_merge_params(params))
    )
    resp.delete_cookie(
        settings.COOKIE_NAME,
        path="/",
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    return resp

@app.get("/debug")
async def debug(request: Request):
    return {
        "scheme": request.url.scheme,
        "headers": {
            k: v for k, v in request.headers.items()
            if k.lower().startswith("x-forwarded") or k == "host"
        }
    }