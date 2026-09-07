"""Read-only SQLite configuration for the dashboard API."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool


class DashboardDatabaseError(RuntimeError):
    pass


def resolve_database_path(database_path: str | Path | None = None) -> Path:
    supplied = database_path or os.environ.get("FYP_DASHBOARD_DATABASE", "data/fyp.db")
    path = Path(supplied).expanduser().resolve(strict=False)
    if not path.exists() or not path.is_file():
        raise DashboardDatabaseError(
            f"dashboard database must already exist as a regular file: {path}"
        )
    return path


def create_read_only_engine(database_path: str | Path) -> Engine:
    """Open an existing SQLite database in genuine read-only/query-only mode."""
    path = resolve_database_path(database_path)
    uri = f"file:{quote(str(path), safe='/')}?mode=ro"

    def _creator() -> sqlite3.Connection:
        connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    engine = create_engine(
        "sqlite+pysqlite://",
        creator=_creator,
        poolclass=NullPool,
        future=True,
    )

    @event.listens_for(engine, "connect")
    def _enforce_query_only(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA query_only=ON")
        cursor.close()

    return engine


def make_read_only_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False, future=True)
