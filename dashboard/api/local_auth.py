"""Small in-memory login boundary for the loopback-only MARS console."""

from __future__ import annotations

import hashlib
import os
import secrets
import time

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.types import ASGIApp, Receive, Scope, Send

COOKIE = "mars_session"
SESSION_SECONDS = 12 * 60 * 60
DEFAULT_USERNAME = "malaika"
DEFAULT_SALT = "mars-local-malaika-v1"
DEFAULT_PASSWORD_HASH = (
    "20b5fc5b43e780e90ffe270c5ceb938ffd3fdfbba91995b80877fb2aba434dcb2"
    "f9a27d075ce55ee84c4dea79b3bcde19d38d80a0cdc40cdce0ed2b06eb7ae1f"
)


class LoginCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class LocalSessions:
    def __init__(self) -> None:
        self.tokens: dict[str, float] = {}

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        self.tokens[token] = time.monotonic() + SESSION_SECONDS
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        expires = self.tokens.get(token, 0)
        if expires <= time.monotonic():
            self.tokens.pop(token, None)
            return False
        return True

    def remove(self, token: str | None) -> None:
        if token:
            self.tokens.pop(token, None)


class RequireLocalSession:
    def __init__(self, app: ASGIApp, sessions: LocalSessions) -> None:
        self.app = app
        self.sessions = sessions

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] == "http"
            and path.startswith("/api/")
            and not path.startswith("/api/auth/")
            and path != "/api/console/status"
            and not self.sessions.valid(Request(scope).cookies.get(COOKIE))
        ):
            await JSONResponse(
                {"error": {"code": "login_required", "message": "Login required."}},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        await self.app(scope, receive, send)


def install_local_auth(app: FastAPI, *, allowed_origins: frozenset[str]) -> None:
    sessions = LocalSessions()
    app.add_middleware(RequireLocalSession, sessions=sessions)
    router = APIRouter(prefix="/api/auth", tags=["Authentication"])

    def approved_origin(request: Request) -> bool:
        return request.headers.get("origin") in allowed_origins

    @router.get("/session")
    async def session(request: Request) -> JSONResponse:
        if not sessions.valid(request.cookies.get(COOKIE)):
            return JSONResponse({"authenticated": False}, status_code=401)
        return JSONResponse({"authenticated": True, "username": username()})

    @router.post("/login")
    async def login(command: LoginCommand, request: Request) -> JSONResponse:
        if not approved_origin(request):
            return JSONResponse({"error": "Login unavailable."}, status_code=403)
        if not verify(command.username, command.password):
            return JSONResponse({"error": "Invalid username or password."}, status_code=401)
        response = JSONResponse({"authenticated": True, "username": username()})
        response.set_cookie(
            COOKIE,
            sessions.create(),
            max_age=SESSION_SECONDS,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return response

    @router.post("/logout", status_code=204)
    async def logout(request: Request) -> Response:
        if not approved_origin(request):
            return JSONResponse({"error": "Logout unavailable."}, status_code=403)
        sessions.remove(request.cookies.get(COOKIE))
        response = Response(status_code=204)
        response.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
        return response

    app.include_router(router)


def username() -> str:
    return os.getenv("MARS_LOGIN_USERNAME", DEFAULT_USERNAME)


def verify(candidate_username: str, candidate_password: str) -> bool:
    salt = os.getenv("MARS_LOGIN_PASSWORD_SALT", DEFAULT_SALT).encode()
    expected = os.getenv("MARS_LOGIN_PASSWORD_HASH", DEFAULT_PASSWORD_HASH)
    actual = hashlib.scrypt(
        candidate_password.encode(), salt=salt, n=2**14, r=8, p=1
    ).hex()
    return secrets.compare_digest(candidate_username, username()) and secrets.compare_digest(
        actual, expected
    )
