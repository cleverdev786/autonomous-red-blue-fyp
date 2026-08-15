"""SQLAlchemy database setup for the dummy store."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for dummy-application tables."""


def create_sqlite_engine(database_url: str) -> Engine:
    """Create the application engine.

    SQLite needs ``check_same_thread=False`` because FastAPI's TestClient may
    use different threads while serving a request.
    """
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, future=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a session factory bound to the supplied engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def session_dependency(
    session_factory: sessionmaker[Session],
) -> Generator[Session, None, None]:
    """Yield one SQLAlchemy session and always close it."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
