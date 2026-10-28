"""Exact clean-state verifier for the target-owned vulnerable-store volume."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select, text

from .config import StoreSettings
from .database import create_session_factory, create_sqlite_engine
from .models import Document, Product, User
from .security import hash_demo_password
from .seed import (
    SCENARIO_FILE_CONTENT,
    SEED_DOCUMENTS,
    SEED_FILE_CONTENT,
    SEED_PRODUCTS,
    SEED_USERS,
)


def _files(directory: Path) -> dict[str, str]:
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("baseline directory is unavailable or unsafe")
    result: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("baseline directory contains a symlink")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = path.read_text(encoding="utf-8")
    return result


def exact_baseline(settings: StoreSettings | None = None) -> bool:
    settings = settings or StoreSettings.from_env()
    engine = create_sqlite_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    with engine.connect() as connection:
        objects = set(connection.execute(text(
            "SELECT type, name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_autoindex_%' AND name NOT LIKE 'sqlite_%'"
        )).all())
    with session_factory() as session:
        users = session.scalars(select(User).order_by(User.id)).all()
        products = session.scalars(select(Product).order_by(Product.id)).all()
        documents = session.scalars(select(Document).order_by(Document.id)).all()
    expected_users = [
        (index, item["username"], item["display_name"], hash_demo_password(item["password"]))
        for index, item in enumerate(SEED_USERS, 1)
    ]
    expected_products = [
        (index, item["name"], item["description"])
        for index, item in enumerate(SEED_PRODUCTS, 1)
    ]
    expected_documents = [
        (index, item["title"], item["stored_filename"])
        for index, item in enumerate(SEED_DOCUMENTS, 1)
    ]
    return (
        objects == {
            ("table", "documents"),
            ("table", "products"),
            ("table", "users"),
            ("index", "ix_products_name"),
            ("index", "ix_users_username"),
        }
        and
        [(row.id, row.username, row.display_name, row.password_hash) for row in users]
        == expected_users
        and [(row.id, row.name, row.description) for row in products]
        == expected_products
        and [(row.id, row.title, row.stored_filename) for row in documents]
        == expected_documents
        and _files(settings.seed_files_dir) == SEED_FILE_CONTENT
        and _files(settings.scenario_files_dir) == SCENARIO_FILE_CONTENT
    )


def main() -> None:
    try:
        passed = exact_baseline()
    except Exception as exc:
        print(json.dumps({"passed": False, "reason": type(exc).__name__}))
        raise SystemExit(2) from exc
    print(json.dumps({"passed": passed, "kind": "exact-target-baseline"}))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
