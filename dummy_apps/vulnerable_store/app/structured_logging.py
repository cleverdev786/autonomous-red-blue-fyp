"""Safe structured JSON event emission for the local vulnerable-store app."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
import re
from typing import Iterator, Mapping
from uuid import uuid4

from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogAttributeValue


RUN_ID_HEADER = "X-FYP-Run-ID"
REQUEST_ID_HEADER = "X-FYP-Request-ID"

_COMPONENT = "vulnerable-store"
_SCHEMA_VERSION = "1.0"
_MAX_ATTRIBUTE_COUNT = 20
_MAX_ATTRIBUTE_STRING_LENGTH = 500
_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$")

_RESERVED_ATTRIBUTE_NAMES = frozenset(
    {
        "schema_version",
        "event_id",
        "timestamp",
        "run_id",
        "request_id",
        "event_type",
        "component",
        "route_name",
        "method",
        "status_code",
        "attributes",
        "error_type",
    }
)
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "authorization",
    "cookie",
    "token",
    "api_key",
    "apikey",
    "secret",
    "database_url",
    "environment",
    "env_var",
)

_RUN_ID: ContextVar[str] = ContextVar("fyp_run_id", default="untracked")
_REQUEST_ID: ContextVar[str] = ContextVar(
    "fyp_request_id",
    default="req-untracked",
)
_METHOD: ContextVar[str] = ContextVar("fyp_method", default="UNKNOWN")
_ROUTE_NAME: ContextVar[str] = ContextVar("fyp_route_name", default="other")


def _valid_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if _IDENTIFIER_PATTERN.fullmatch(stripped) is None:
        return None
    return stripped


def resolve_run_id(value: str | None) -> str:
    """Accept only bounded identifier-shaped correlation values."""
    return _valid_identifier(value) or "untracked"


def resolve_request_id(value: str | None) -> str:
    """Accept one bounded request ID or create an opaque local fallback."""
    return _valid_identifier(value) or f"req-{uuid4().hex[:24]}"


def neutral_route_name(path: str) -> str:
    """Map internal baseline/scenario paths to non-ground-truth route names."""
    if path == "/health":
        return "health"
    if path in {"/login", "/scenarios/sql-injection/login"}:
        return "login"
    if path in {"/search", "/scenarios/xss/search"}:
        return "search"
    if path == "/documents":
        return "documents"
    if path.startswith("/files/") or path == "/scenarios/path-traversal/read":
        return "file_read"
    return "other"


def _safe_attribute_key(key: object) -> str | None:
    candidate = str(key).strip()
    lowered = candidate.lower()
    if not candidate or _IDENTIFIER_PATTERN.fullmatch(candidate) is None:
        return None
    if lowered in _RESERVED_ATTRIBUTE_NAMES:
        return None
    if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
        return None
    return candidate


def _safe_attribute_value(value: object) -> LogAttributeValue:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if len(text) > _MAX_ATTRIBUTE_STRING_LENGTH:
        text = text[:_MAX_ATTRIBUTE_STRING_LENGTH]
    return text


def sanitize_attributes(
    attributes: Mapping[str, object] | None,
) -> dict[str, LogAttributeValue]:
    """Bound attributes and discard reserved/sensitive caller-supplied keys."""
    if not attributes:
        return {}

    safe: dict[str, LogAttributeValue] = {}
    for raw_key, raw_value in attributes.items():
        if len(safe) >= _MAX_ATTRIBUTE_COUNT:
            break
        key = _safe_attribute_key(raw_key)
        if key is None:
            continue
        safe[key] = _safe_attribute_value(raw_value)
    return safe


@contextmanager
def request_logging_context(
    *,
    run_id: str,
    request_id: str,
    method: str,
    route_name: str,
) -> Iterator[None]:
    """Bind request correlation for route-level event emitters."""
    tokens = (
        (_RUN_ID, _RUN_ID.set(run_id)),
        (_REQUEST_ID, _REQUEST_ID.set(request_id)),
        (_METHOD, _METHOD.set(method)),
        (_ROUTE_NAME, _ROUTE_NAME.set(route_name)),
    )
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def emit_structured_event(
    *,
    event_type: ApplicationEventType,
    attributes: Mapping[str, object] | None = None,
    status_code: int | None = None,
    error_type: str | None = None,
) -> ApplicationLogEvent:
    """Emit one validated JSON line with trusted structural fields.

    Caller attributes are always nested under ``attributes`` after filtering.
    They can never replace structural event fields.
    """
    event = ApplicationLogEvent(
        schema_version=_SCHEMA_VERSION,
        event_id=f"evt-{uuid4().hex[:24]}",
        timestamp=datetime.now(UTC),
        run_id=_RUN_ID.get(),
        request_id=_REQUEST_ID.get(),
        event_type=event_type,
        component=_COMPONENT,
        route_name=_ROUTE_NAME.get(),
        method=_METHOD.get(),
        status_code=status_code,
        attributes=sanitize_attributes(attributes),
        error_type=_valid_identifier(error_type) if error_type else None,
    )
    print(event.model_dump_json(), flush=True)
    return event
