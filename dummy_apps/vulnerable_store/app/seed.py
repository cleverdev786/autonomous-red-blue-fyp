"""Deterministic database and local-file seeding for the dummy store."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy import delete, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .database import Base
from .models import Document, Product, User
from .security import hash_demo_password

SEED_USERS = (
    {
        "username": "student1",
        "display_name": "Demo Student One",
        "password": "demo-pass-1",
    },
    {
        "username": "student2",
        "display_name": "Demo Student Two",
        "password": "demo-pass-2",
    },
)

SEED_PRODUCTS = (
    {
        "name": "Secure Coding Handbook",
        "description": "Synthetic catalog item for normal search behavior.",
    },
    {
        "name": "Web Testing Notebook",
        "description": "Synthetic catalog item used in the controlled local FYP app.",
    },
    {
        "name": "Blue Team Checklist",
        "description": "Synthetic product record for regression testing.",
    },
)

SEED_DOCUMENTS = (
    {
        "title": "Welcome Guide",
        "stored_filename": "welcome.txt",
    },
    {
        "title": "Security Lab Rules",
        "stored_filename": "security-lab-rules.txt",
    },
)

SEED_FILE_CONTENT = {
    "welcome.txt": (
        "Welcome to the local FYP Vulnerable Store baseline application.\n"
        "This file contains synthetic demonstration content only.\n"
    ),
    "security-lab-rules.txt": (
        "Security Lab Rules\n"
        "1. Use only the local dummy application.\n"
        "2. Do not test external or unauthorized systems.\n"
        "3. Keep all data synthetic.\n"
    ),
}

SCENARIO_FILE_CONTENT = {
    "public/guide.txt": (
        "Public scenario guide. This file is intended to be downloadable.\n"
    ),
    "private/demo-secret.txt": (
        "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only\n"
    ),
}


def _recreate_owned_directory(directory: Path) -> None:
    """Clear one configured target-owned directory without following symlinks."""
    if directory.is_symlink():
        raise RuntimeError("refusing to reset a symlinked target directory")
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)


def ensure_seed_files(seed_files_dir: Path) -> None:
    """Create deterministic synthetic baseline document files."""
    _recreate_owned_directory(seed_files_dir)
    for filename, content in SEED_FILE_CONTENT.items():
        (seed_files_dir / filename).write_text(content, encoding="utf-8")


def ensure_scenario_files(scenario_files_dir: Path) -> None:
    """Create a bounded filesystem sandbox for the path-traversal scenario.

    The deliberate flaw allows movement from ``public`` to ``private`` inside
    this sandbox. A separate safety check still prevents escape from the
    scenario sandbox into the repository or host filesystem.
    """
    _recreate_owned_directory(scenario_files_dir)
    public_dir = scenario_files_dir / "public"
    private_dir = scenario_files_dir / "private"
    public_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)

    for relative, content in SCENARIO_FILE_CONTENT.items():
        (scenario_files_dir / relative).write_text(content, encoding="utf-8")


def reset_database(
    engine: Engine,
    session_factory: sessionmaker[Session],
    seed_files_dir: Path,
    scenario_files_dir: Path,
) -> None:
    """Restore the dummy application to a known deterministic state."""
    ensure_seed_files(seed_files_dir)
    ensure_scenario_files(scenario_files_dir)
    with engine.begin() as connection:
        rows = connection.execute(text(
            "SELECT type, name FROM sqlite_master "
            "WHERE type IN ('table', 'view', 'trigger') AND name NOT LIKE 'sqlite_%'"
        )).all()
        for object_type, name in sorted(
            rows, key=lambda item: {"trigger": 0, "view": 1, "table": 2}[item[0]],
        ):
            if not isinstance(name, str) or '"' in name:
                raise RuntimeError("unsafe SQLite object name during reset")
            keyword = {"table": "TABLE", "view": "VIEW", "trigger": "TRIGGER"}[object_type]
            connection.exec_driver_sql(f'DROP {keyword} "{name}"')
    Base.metadata.create_all(engine)

    with session_factory() as session:
        session.execute(delete(Document))
        session.execute(delete(Product))
        session.execute(delete(User))

        session.add_all(
            User(
                username=item["username"],
                display_name=item["display_name"],
                password_hash=hash_demo_password(item["password"]),
            )
            for item in SEED_USERS
        )
        session.add_all(Product(**item) for item in SEED_PRODUCTS)
        session.add_all(Document(**item) for item in SEED_DOCUMENTS)
        session.commit()
