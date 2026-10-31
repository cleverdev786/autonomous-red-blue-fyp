"""Versioned, observational remediation decisions and pre-verification outcomes.

These schemas do not authorize patch application, filesystem access, or Git work.
Legacy patch artifact schemas remain unchanged.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.common import Identifier, VulnerabilityClass


class RepairStrategy(str, Enum):
    SQLALCHEMY_NAMED_BIND = "sqlalchemy_named_bind"
    HTML_TEXT_ESCAPE = "html_text_escape"
    CANONICAL_PUBLIC_ROOT = "canonical_public_root"


class NoActionReason(str, Enum):
    BENIGN = "benign"
    UNSUPPORTED = "unsupported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class RemediationDisposition(str, Enum):
    PREPARED = "prepared"
    NO_ACTION = "no_action"
    UNSUPPORTED = "unsupported"
    INVALID_OUTPUT = "invalid_output"
    COMPILER_REJECTED = "compiler_rejected"
    POLICY_BLOCKED = "policy_blocked"
    PROVIDER_FAILED = "provider_failed"


class RemediationDecision(BaseModel):
    """Untrusted model decision; no code, path, SQL, imports, or commands."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"]
    action: Literal["repair", "no_action"]
    vulnerability_class: VulnerabilityClass | None = None
    strategy: RepairStrategy | None = None
    tainted_symbol: str | None = Field(
        default=None, max_length=100,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,2}$",
    )
    no_action_reason: NoActionReason | None = None

    @model_validator(mode="after")
    def validate_action(self) -> "RemediationDecision":
        if self.action == "repair":
            mapping = {
                VulnerabilityClass.SQL_INJECTION: RepairStrategy.SQLALCHEMY_NAMED_BIND,
                VulnerabilityClass.XSS: RepairStrategy.HTML_TEXT_ESCAPE,
                VulnerabilityClass.PATH_TRAVERSAL: RepairStrategy.CANONICAL_PUBLIC_ROOT,
            }
            if (
                self.vulnerability_class is None
                or self.strategy is None
                or self.tainted_symbol is None
                or self.no_action_reason is not None
                or mapping.get(self.vulnerability_class) != self.strategy
            ):
                raise ValueError("repair requires a compatible class, strategy and tainted symbol")
        elif (
            self.vulnerability_class is not None
            or self.strategy is not None
            or self.tainted_symbol is not None
            or self.no_action_reason is None
        ):
            raise ValueError("no_action permits only a no_action_reason")
        return self


_SHA = r"^[0-9a-f]{64}$"


class RemediationAttemptResult(BaseModel):
    """New, versioned evidence of preparation or a terminal non-patch outcome.

    A PREPARED result refers to an existing, separate legacy patch artifact.
    Never substitute this for PatchGenerationResult or an accepted patch.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"]
    run_id: Identifier
    target_id: Identifier
    attempt_number: int = Field(ge=1)
    disposition: RemediationDisposition
    reason_code: Identifier
    decision: RemediationDecision | None = None
    model_input_sha256: str | None = Field(default=None, pattern=_SHA)
    raw_response_sha256: str | None = Field(default=None, pattern=_SHA)
    source_sha256: str | None = Field(default=None, pattern=_SHA)
    compiler_version: Identifier | None = None
    compiler_sha256: str | None = Field(default=None, pattern=_SHA)
    prepared_diff_sha256: str | None = Field(default=None, pattern=_SHA)
    legacy_generation_artifact_sha256: str | None = Field(default=None, pattern=_SHA)
    policy_event_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_provenance(self) -> "RemediationAttemptResult":
        d = self.disposition
        if d == RemediationDisposition.PREPARED:
            if (
                self.decision is None or self.decision.action != "repair"
                or not all((self.model_input_sha256, self.raw_response_sha256,
                            self.source_sha256, self.compiler_version,
                            self.compiler_sha256, self.prepared_diff_sha256,
                            self.legacy_generation_artifact_sha256))
            ):
                raise ValueError("prepared requires a repair decision and full linked provenance")
        elif self.prepared_diff_sha256 is not None or self.legacy_generation_artifact_sha256 is not None:
            raise ValueError("non-prepared outcomes cannot claim a prepared patch")

        if d == RemediationDisposition.NO_ACTION:
            if self.decision is not None and (
                self.decision.action != "no_action"
                or self.decision.no_action_reason not in {
                    NoActionReason.BENIGN, NoActionReason.INSUFFICIENT_EVIDENCE,
                }
            ):
                raise ValueError("no_action requires benign or insufficient-evidence refusal")
        elif d == RemediationDisposition.UNSUPPORTED:
            if (
                self.decision is None or self.decision.action != "no_action"
                or self.decision.no_action_reason != NoActionReason.UNSUPPORTED
            ):
                raise ValueError("unsupported requires an explicit unsupported decision")
        elif d == RemediationDisposition.COMPILER_REJECTED:
            if (
                self.decision is None or self.decision.action != "repair"
                or not all((self.source_sha256, self.compiler_version, self.compiler_sha256))
            ):
                raise ValueError("compiler rejection needs a repair decision and compiler identity")
        elif d == RemediationDisposition.POLICY_BLOCKED:
            from schemas.common import PolicyReasonCode
            if self.policy_event_id is None or self.reason_code not in {
                value.value for value in PolicyReasonCode if value != PolicyReasonCode.ALLOWED
            }:
                raise ValueError("policy_blocked requires policy reason and blocked event")
        elif d in {RemediationDisposition.INVALID_OUTPUT, RemediationDisposition.PROVIDER_FAILED}:
            if self.decision is not None:
                raise ValueError("invalid/provider failure cannot claim a validated decision")
            if d == RemediationDisposition.INVALID_OUTPUT and self.raw_response_sha256 is None:
                raise ValueError("invalid output requires captured raw-response evidence")

        if self.decision is not None and not all(
            (self.model_input_sha256, self.raw_response_sha256)
        ):
            raise ValueError("validated model decision requires input and raw-output hashes")
        if d == RemediationDisposition.NO_ACTION and self.decision is None and any((
            self.model_input_sha256, self.raw_response_sha256,
            self.compiler_version, self.source_sha256,
        )):
            raise ValueError("trusted benign bypass must not claim model/compilation evidence")
        if d != RemediationDisposition.POLICY_BLOCKED and self.policy_event_id is not None:
            raise ValueError("policy event may be cited only for policy-blocked disposition")
        if self.compiler_version is None and self.compiler_sha256 is not None:
            raise ValueError("compiler hash requires a compiler version")
        if self.compiler_version is not None and self.compiler_sha256 is None:
            raise ValueError("compiler version requires a compiler hash")
        return self
