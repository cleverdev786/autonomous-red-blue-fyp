"""Configuration for the Vulnerable Store baseline application."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = APP_ROOT.parents[1]


@dataclass(frozen=True, slots=True)
class StoreSettings:
    """Runtime settings for the local dummy application."""

    database_url: str
    seed_files_dir: Path
    scenario_files_dir: Path

    @classmethod
    def from_env(cls) -> "StoreSettings":
        database_url = os.getenv(
            "VULNERABLE_STORE_DATABASE_URL",
            f"sqlite:///{(PROJECT_ROOT / 'data' / 'vulnerable_store.db').as_posix()}",
        )
        seed_files_dir = Path(
            os.getenv(
                "VULNERABLE_STORE_SEED_FILES_DIR",
                str(APP_ROOT / "seed_files"),
            )
        ).expanduser().resolve(strict=False)
        scenario_files_dir = Path(
            os.getenv(
                "VULNERABLE_STORE_SCENARIO_FILES_DIR",
                str(APP_ROOT / "scenario_files"),
            )
        ).expanduser().resolve(strict=False)

        return cls(
            database_url=database_url,
            seed_files_dir=seed_files_dir,
            scenario_files_dir=scenario_files_dir,
        )
