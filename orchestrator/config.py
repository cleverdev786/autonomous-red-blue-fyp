"""Minimal project configuration for the repository-foundation milestone.

This module intentionally uses only the Python standard library.
Typed Pydantic schemas are introduced in the next milestone.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_project_path(value: str) -> Path:
    """Resolve a configured path without creating or touching the filesystem."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve(strict=False)


@dataclass(frozen=True, slots=True)
class ProjectSettings:
    """Small immutable settings object used before the full config layer exists."""

    environment: str
    data_dir: Path
    database_url: str

    @classmethod
    def from_env(cls) -> "ProjectSettings":
        """Load non-secret foundation settings from environment variables."""
        return cls(
            environment=os.getenv("FYP_ENV", "development"),
            data_dir=_resolve_project_path(os.getenv("FYP_DATA_DIR", "./data")),
            database_url=os.getenv(
                "FYP_DATABASE_URL",
                "sqlite:///./data/fyp.db",
            ),
        )
