"""Reset the local baseline dummy application database."""

from __future__ import annotations

from .config import StoreSettings
from .database import create_session_factory, create_sqlite_engine
from .seed import reset_database


def main() -> None:
    settings = StoreSettings.from_env()
    engine = create_sqlite_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    reset_database(
        engine=engine,
        session_factory=session_factory,
        seed_files_dir=settings.seed_files_dir,
        scenario_files_dir=settings.scenario_files_dir,
    )
    print("Vulnerable Store baseline reset complete.")


if __name__ == "__main__":
    main()
