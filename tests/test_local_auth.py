"""Application-wide local login contract."""

import asyncio
import hashlib

import httpx

from dashboard.api.console import create_console_app


def request(app, method, path, **kwargs):
    async def send():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_login_protects_application_api_with_http_only_session(tmp_path, monkeypatch):
    salt = "test-salt"
    password = "test-password"
    digest = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2**14, r=8, p=1
    ).hex()
    monkeypatch.setenv("MARS_LOGIN_USERNAME", "test-user")
    monkeypatch.setenv("MARS_LOGIN_PASSWORD_SALT", salt)
    monkeypatch.setenv("MARS_LOGIN_PASSWORD_HASH", digest)
    app = create_console_app(
        database_path=tmp_path / "missing.db",
        mars_workspace_db=tmp_path / "mars.db",
        red_state_db=tmp_path / "red.db",
    )

    protected_path = "/api/red/operator/csrf"
    assert request(app, "GET", protected_path).status_code == 401
    assert request(app, "POST", "/api/auth/login", json={
        "username": "test-user", "password": "wrong",
    }, headers={"Origin": "http://127.0.0.1:8090"}).status_code == 401

    logged_in = request(app, "POST", "/api/auth/login", json={
        "username": "test-user", "password": password,
    }, headers={"Origin": "http://127.0.0.1:8090"})
    assert logged_in.status_code == 200
    cookie = logged_in.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    cookie_header = {"Cookie": f"mars_session={logged_in.cookies['mars_session']}"}
    assert request(app, "GET", "/api/auth/session", headers=cookie_header).status_code == 200
    assert request(app, "GET", protected_path, headers=cookie_header).status_code == 200


def test_login_rejects_foreign_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("MARS_LOGIN_USERNAME", "test-user")
    monkeypatch.setenv("MARS_LOGIN_PASSWORD_SALT", "test-salt")
    monkeypatch.setenv("MARS_LOGIN_PASSWORD_HASH", "0" * 128)
    app = create_console_app(
        database_path=tmp_path / "missing.db", red_state_db=tmp_path / "red.db"
    )
    response = request(app, "POST", "/api/auth/login", json={
        "username": "test-user", "password": "anything",
    }, headers={"Origin": "https://foreign.example"})
    assert response.status_code == 403
