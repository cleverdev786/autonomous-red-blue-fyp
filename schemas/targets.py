"""Target and registered security-test definitions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.common import (
    HttpMethod,
    Identifier,
    NonEmptyText,
    RelativeProjectPath,
    VulnerabilityClass,
)


class EndpointDefinition(BaseModel):
    """One endpoint explicitly approved for controlled local testing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: Identifier
    path: str = Field(min_length=1, max_length=300)
    allowed_methods: tuple[HttpMethod, ...] = Field(min_length=1)
    input_fields: tuple[Identifier, ...] = ()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("endpoint path must start with '/'")
        if "://" in value:
            raise ValueError("endpoint path must not contain a URL scheme")
        return value


class TargetDefinition(BaseModel):
    """Human-controlled registry entry for one approved dummy target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: Identifier
    container_name: Identifier
    hostname: Identifier
    port: int = Field(ge=1, le=65535)
    scheme: str = Field(default="http")
    endpoints: tuple[EndpointDefinition, ...] = Field(min_length=1)
    allowed_test_ids: tuple[Identifier, ...] = Field(min_length=1)
    source_root: RelativeProjectPath
    writable_patch_roots: tuple[RelativeProjectPath, ...] = Field(min_length=1)
    log_sources: tuple[RelativeProjectPath, ...] = Field(min_length=1)
    reset_operation_id: Identifier
    max_requests_per_attempt: int = Field(default=5, ge=1, le=100)
    max_attempt_duration_seconds: int = Field(default=30, ge=1, le=600)

    @field_validator("scheme")
    @classmethod
    def only_local_http_scheme(cls, value: str) -> str:
        if value != "http":
            raise ValueError("MVP target scheme must be 'http'")
        return value

    @field_validator("source_root", "writable_patch_roots", "log_sources")
    @classmethod
    def reject_absolute_or_parent_paths(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            normalized = str(item).replace("\\", "/")
            if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
                raise ValueError("registry paths must be project-relative and must not escape with '..'")
        return value

    @model_validator(mode="after")
    def unique_endpoint_ids(self) -> "TargetDefinition":
        endpoint_ids = [endpoint.endpoint_id for endpoint in self.endpoints]
        if len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("endpoint_id values must be unique within a target")
        if len(self.allowed_test_ids) != len(set(self.allowed_test_ids)):
            raise ValueError("allowed_test_ids must be unique")
        return self


class SecurityTestDefinition(BaseModel):
    """Registered deterministic security-test template metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    vulnerability_class: VulnerabilityClass
    target_id: Identifier
    endpoint_id: Identifier
    method: HttpMethod
    allowed_parameter_names: tuple[Identifier, ...] = ()
    request_template_id: Identifier
    success_evidence_rule_id: Identifier
    max_requests: int = Field(default=1, ge=1, le=20)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    description: NonEmptyText
