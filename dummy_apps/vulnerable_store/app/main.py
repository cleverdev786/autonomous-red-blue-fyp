"""FastAPI baseline application with controlled vulnerable scenarios."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from schemas.logging import ApplicationEventType

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
from .structured_logging import (
    REQUEST_ID_HEADER,
    RUN_ID_HEADER,
    emit_structured_event,
    neutral_route_name,
    request_logging_context,
    resolve_request_id,
    resolve_run_id,
)


def _safe_seed_file(seed_dir: Path, stored_filename: str) -> Path:
    """Resolve one database-controlled seed filename inside the approved directory."""
    candidate = (seed_dir / stored_filename).resolve(strict=False)
    root = seed_dir.resolve(strict=False)

    if candidate.parent != root:
        raise HTTPException(status_code=404, detail="Document not found")

    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Document file not found")

    return candidate


def create_app(
    settings: StoreSettings | None = None,
    *,
    reset_on_start: bool = True,
) -> FastAPI:
    """Create one local dummy-app instance with bounded structured logging."""
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

    @app.middleware("http")
    async def structured_event_context(request: Request, call_next):
        run_id = resolve_run_id(request.headers.get(RUN_ID_HEADER))
        request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        route_name = neutral_route_name(request.url.path)
        method = request.method.upper()

        with request_logging_context(
            run_id=run_id,
            request_id=request_id,
            method=method,
            route_name=route_name,
        ):
            try:
                response = await call_next(request)
            except Exception as exc:
                emit_structured_event(
                    event_type=ApplicationEventType.APPLICATION_ERROR,
                    status_code=500,
                    error_type=exc.__class__.__name__,
                )
                raise

            emit_structured_event(
                event_type=ApplicationEventType.HTTP_REQUEST,
                status_code=response.status_code,
            )
            return response

    @app.exception_handler(RequestValidationError)
    async def structured_validation_error(
        request: Request,
        exc: RequestValidationError,
    ):
        emit_structured_event(
            event_type=ApplicationEventType.VALIDATION_EVENT,
            attributes={
                "accepted": False,
                "error_count": len(exc.errors()),
            },
            status_code=422,
        )
        return await request_validation_exception_handler(request, exc)

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
    def login(
        payload: LoginRequest,
        session: Session = Depends(get_session),
    ) -> LoginResponse:
        user = session.scalar(select(User).where(User.username == payload.username))
        authenticated = (
            user is not None
            and verify_demo_password(payload.password, user.password_hash)
        )
        emit_structured_event(
            event_type=ApplicationEventType.DATABASE_EVENT,
            attributes={
                "operation": "login_lookup",
                "username": payload.username,
                "matched": user is not None,
                "authenticated": authenticated,
            },
        )

        if not authenticated or user is None:
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
        emit_structured_event(
            event_type=ApplicationEventType.VALIDATION_EVENT,
            attributes={"field": "q", "value": q, "accepted": True},
        )
        query = select(Product).order_by(Product.id)
        if q:
            pattern = f"%{q}%"
            query = query.where(
                Product.name.ilike(pattern) | Product.description.ilike(pattern)
            )

        products = session.scalars(query).all()
        emit_structured_event(
            event_type=ApplicationEventType.DATABASE_EVENT,
            attributes={
                "operation": "product_search",
                "query": q,
                "result_count": len(products),
            },
        )
        return [
            ProductResponse(
                id=product.id,
                name=product.name,
                description=product.description,
            )
            for product in products
        ]

    @app.get("/documents", response_model=list[DocumentResponse])
    def list_documents(
        session: Session = Depends(get_session),
    ) -> list[DocumentResponse]:
        documents = session.scalars(select(Document).order_by(Document.id)).all()
        emit_structured_event(
            event_type=ApplicationEventType.DATABASE_EVENT,
            attributes={
                "operation": "document_listing",
                "result_count": len(documents),
            },
        )
        return [DocumentResponse(id=item.id, title=item.title) for item in documents]

    @app.get("/files/{document_id}")
    def download_document(
        document_id: int,
        session: Session = Depends(get_session),
    ) -> FileResponse:
        document = session.get(Document, document_id)
        if document is None:
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"document_id": document_id, "outcome": "not_found"},
                status_code=404,
            )
            raise HTTPException(status_code=404, detail="Document not found")

        path = _safe_seed_file(
            resolved_settings.seed_files_dir,
            document.stored_filename,
        )
        emit_structured_event(
            event_type=ApplicationEventType.FILE_ACCESS_EVENT,
            attributes={"document_id": document_id, "outcome": "allowed"},
        )

        return FileResponse(
            path=path,
            media_type="text/plain",
            filename=document.stored_filename,
        )

    return app


app = create_app()
