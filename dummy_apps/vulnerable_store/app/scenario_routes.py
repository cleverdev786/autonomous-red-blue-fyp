"""Deliberately vulnerable routes for the controlled local FYP scenarios.

These endpoints are intentionally unsafe and must never be exposed publicly.
They exist only so the Red/Blue framework can detect, remediate, and verify
known weaknesses in a bounded local environment.

Important safety distinction:
- SQLi and XSS affect only synthetic application data/output.
- The traversal scenario intentionally escapes its *public* directory, but a
  lab-sandbox boundary still prevents escape into the repository or host.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from schemas.logging import ApplicationEventType

from .api_schemas import LoginRequest, LoginResponse
from .security import hash_demo_password
from .structured_logging import emit_structured_event


def build_scenario_router(*, get_session, scenario_files_dir: Path) -> APIRouter:
    """Create scenario routes bound to the current application dependencies."""

    local_router = APIRouter(
        prefix="/scenarios",
        tags=["deliberately-vulnerable-scenarios"],
    )

    @local_router.post("/sql-injection/login", response_model=LoginResponse)
    def vulnerable_login(
        payload: LoginRequest,
        session: Session = Depends(get_session),
    ) -> LoginResponse:
        """Intentionally vulnerable SQL login for synthetic local data only."""
        password_hash = hash_demo_password(payload.password)

        # DELIBERATE VULNERABILITY: string concatenation into a SQL statement.
        query = (
            "SELECT username, display_name FROM users "
            f"WHERE username = '{payload.username}' "
            f"AND password_hash = '{password_hash}' "
            "LIMIT 1"
        )

        row = session.execute(text(query)).mappings().first()
        emit_structured_event(
            event_type=ApplicationEventType.DATABASE_EVENT,
            attributes={
                "operation": "login_lookup",
                "username": payload.username,
                "matched": row is not None,
                "authenticated": row is not None,
            },
        )
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        return LoginResponse(
            authenticated=True,
            username=str(row["username"]),
            display_name=str(row["display_name"]),
        )

    @local_router.get("/xss/search", response_class=HTMLResponse)
    def vulnerable_search(q: str = Query(default="", max_length=200)) -> HTMLResponse:
        """Intentionally reflect query text into HTML without escaping."""
        emit_structured_event(
            event_type=ApplicationEventType.VALIDATION_EVENT,
            attributes={"field": "q", "value": q, "accepted": True},
        )

        # DELIBERATE VULNERABILITY: q is inserted directly into HTML.
        body = (
            "<!doctype html><html><body>"
            "<h1>Scenario Search</h1>"
            f"<p id=\"result\">Search term: {q}</p>"
            "</body></html>"
        )
        return HTMLResponse(content=body)

    @local_router.get("/path-traversal/read", response_class=PlainTextResponse)
    def vulnerable_file_read(
        path: str = Query(min_length=1, max_length=200),
    ) -> PlainTextResponse:
        """Intentionally allow traversal from public/ to private/ in the sandbox."""
        scenario_root = scenario_files_dir.resolve(strict=False)
        intended_public_root = (scenario_root / "public").resolve(strict=False)

        # DELIBERATE VULNERABILITY: user path is joined to the intended public
        # root and may contain ../, allowing access to scenario_root/private.
        candidate = (intended_public_root / path).resolve(strict=False)

        # SAFETY BOUNDARY: the educational traversal cannot escape the isolated
        # synthetic scenario directory into the project or host filesystem.
        try:
            candidate.relative_to(scenario_root)
        except ValueError as exc:
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": path, "outcome": "sandbox_blocked"},
                status_code=403,
            )
            raise HTTPException(
                status_code=403,
                detail="Scenario sandbox escape blocked",
            ) from exc

        if not candidate.is_file():
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": path, "outcome": "not_found"},
                status_code=404,
            )
            raise HTTPException(status_code=404, detail="Scenario file not found")

        emit_structured_event(
            event_type=ApplicationEventType.FILE_ACCESS_EVENT,
            attributes={"requested_path": path, "outcome": "allowed"},
        )
        return PlainTextResponse(candidate.read_text(encoding="utf-8"))

    return local_router
