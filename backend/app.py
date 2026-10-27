"""Canonical FastAPI entrypoint for the MARS security workspace.

This reuses the existing application factory. No second app, route tree,
security runner, CORS policy, or database is created here.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from dashboard.api.console import app
from dashboard.api.console import create_console_app


def create_app(
    database_path: str | Path | None = None,
    *,
    mars_workspace_db: str | Path | None = None,
    red_state_db: str | Path | None = None,
) -> FastAPI:
    """Configure a MARS instance while preserving the existing API contracts."""
    return create_console_app(
        database_path=database_path,
        mars_workspace_db=mars_workspace_db,
        red_state_db=red_state_db,
    )


__all__ = ["app", "create_app"]
