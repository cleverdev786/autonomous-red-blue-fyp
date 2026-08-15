"""FastAPI baseline application.

Milestone 3 intentionally contains only normal application behavior.
Deliberate vulnerabilities are introduced in the next milestone.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api_schemas import (
    DocumentResponse,
    HealthResponse,
    LoginRequest,
    LoginResponse,
    ProductResponse,
)
from .config import StoreSettings
from .database import create_session_factory, create_sqlite_engine
from .models import Document, Product, User
from .security import verify_demo_password
from .scenario_routes import build_scenario_router
from .seed import reset_database


def _safe_seed_file(seed_dir: Path, stored_filename: str) -> Path:
    """Resolve one database-controlled seed filename inside the approved directory."""
    candidate = (seed_dir / stored_filename).resolve(strict=False)
    root = seed_dir.resolve(strict=False)

    if candidate.parent != root:
        raise HTTPException(status_code=404, detail="Document not found")

    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Document file not found")

    return candidate


def create_app(settings: StoreSettings | None = None, *, reset_on_start: bool = True) -> FastAPI:
    """Create one baseline dummy-app instance.

    Tests pass an isolated temporary SQLite database. The normal local app uses
    the repository's data directory.
    """
    resolved_settings = settings or StoreSettings.from_env()
    engine = create_sqlite_engine(resolved_settings.database_url)
    session_factory = create_session_factory(engine)

    if reset_on_start:
        reset_database(
            engine=engine,
            session_factory=session_factory,
            seed_files_dir=resolved_settings.seed_files_dir,
            scenario_files_dir=resolved_settings.scenario_files_dir,
        )

    app = FastAPI(
        title="FYP Vulnerable Store - Controlled Scenarios",
        version="0.1.0",
        description=(
            "Local dummy application with normal baseline routes and three "
            "separate deliberately vulnerable FYP scenario routes."
        ),
    )

    app.state.settings = resolved_settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    def get_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.include_router(
        build_scenario_router(
            get_session=get_session,
            scenario_files_dir=resolved_settings.scenario_files_dir,
        )
    )

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", app="vulnerable-store-baseline")

    @app.post("/login", response_model=LoginResponse)
    def login(payload: LoginRequest, session: Session = Depends(get_session)) -> LoginResponse:
        user = session.scalar(select(User).where(User.username == payload.username))

        if user is None or not verify_demo_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        return LoginResponse(
            authenticated=True,
            username=user.username,
            display_name=user.display_name,
        )

    @app.get("/search", response_model=list[ProductResponse])
    def search(
        q: str = Query(default="", max_length=120),
        session: Session = Depends(get_session),
    ) -> list[ProductResponse]:
        query = select(Product).order_by(Product.id)
        if q:
            pattern = f"%{q}%"
            query = query.where(
                Product.name.ilike(pattern) | Product.description.ilike(pattern)
            )

        products = session.scalars(query).all()
        return [
            ProductResponse(
                id=product.id,
                name=product.name,
                description=product.description,
            )
            for product in products
        ]

    @app.get("/documents", response_model=list[DocumentResponse])
    def list_documents(session: Session = Depends(get_session)) -> list[DocumentResponse]:
        documents = session.scalars(select(Document).order_by(Document.id)).all()
        return [DocumentResponse(id=item.id, title=item.title) for item in documents]

    @app.get("/files/{document_id}")
    def download_document(
        document_id: int,
        session: Session = Depends(get_session),
    ) -> FileResponse:
        document = session.get(Document, document_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        path = _safe_seed_file(
            resolved_settings.seed_files_dir,
            document.stored_filename,
        )

        return FileResponse(
            path=path,
            media_type="text/plain",
            filename=document.stored_filename,
        )

    return app


app = create_app()
