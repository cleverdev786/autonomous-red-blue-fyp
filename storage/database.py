"""Restricted local SQLite database construction for research evidence."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from storage.models import Base


class DatabaseConfigurationError(ValueError):
    pass


def create_database_engine(database_url: str, *, project_root: Path | None = None) -> Engine:
    """Create a SQLite-only SQLAlchemy engine and enforce foreign keys."""
    if database_url == "sqlite:///:memory:":
        url = database_url
    elif database_url.startswith("sqlite:///"):
        raw = database_url.removeprefix("sqlite:///")
        path = Path(raw).expanduser()
        if not path.is_absolute():
            base = (project_root or Path.cwd()).resolve(strict=False)
            path = (base / path).resolve(strict=False)
        if project_root is not None:
            root = project_root.resolve(strict=False)
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise DatabaseConfigurationError("SQLite database path must stay inside project_root") from exc
        path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{path}"
    else:
        raise DatabaseConfigurationError("Milestone 15 supports only local SQLite URLs")

    engine = create_engine(url, future=True)

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def initialize_database(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
