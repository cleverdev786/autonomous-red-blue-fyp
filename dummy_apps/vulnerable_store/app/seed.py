"""Deterministic database and local-file seeding for the dummy store."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete
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


def ensure_seed_files(seed_files_dir: Path) -> None:
    """Create deterministic synthetic baseline document files."""
    seed_files_dir.mkdir(parents=True, exist_ok=True)

    files = {
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

    for filename, content in files.items():
        (seed_files_dir / filename).write_text(content, encoding="utf-8")


def ensure_scenario_files(scenario_files_dir: Path) -> None:
    """Create a bounded filesystem sandbox for the path-traversal scenario.

    The deliberate flaw allows movement from ``public`` to ``private`` inside
    this sandbox. A separate safety check still prevents escape from the
    scenario sandbox into the repository or host filesystem.
    """
    public_dir = scenario_files_dir / "public"
    private_dir = scenario_files_dir / "private"
    public_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)

    (public_dir / "guide.txt").write_text(
        "Public scenario guide. This file is intended to be downloadable.\n",
        encoding="utf-8",
    )
    (private_dir / "demo-secret.txt").write_text(
        "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only\n",
        encoding="utf-8",
    )


def reset_database(
    engine: Engine,
    session_factory: sessionmaker[Session],
    seed_files_dir: Path,
    scenario_files_dir: Path,
) -> None:
    """Restore the dummy application to a known deterministic state."""
    ensure_seed_files(seed_files_dir)
    ensure_scenario_files(scenario_files_dir)
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
