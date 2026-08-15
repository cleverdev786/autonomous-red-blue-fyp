"""Internal contracts for deterministic registered security tests."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping

from schemas.common import HttpMethod
from schemas.red_team import EvidenceItem, HttpExchangeEvidence


@dataclass(frozen=True, slots=True)
class RequestStep:
    """One fixed request step from code-defined test logic.

    No raw URL is stored here. The controlled executor resolves endpoint_id via
    the trusted target registry and constructs the local destination itself.
    """

    step_id: str
    endpoint_id: str
    method: HttpMethod
    query_params: Mapping[str, str] = field(default_factory=dict)
    json_body: Mapping[str, Any] | None = None


class RegisteredSecurityTest(ABC):
    """Base class for one code-defined local security test."""

    test_id: str

    @abstractmethod
    def build_steps(self) -> tuple[RequestStep, ...]:
        """Return the fixed request sequence for this registered test."""

    @abstractmethod
    def evaluate(
        self,
        exchanges: tuple[HttpExchangeEvidence, ...],
    ) -> tuple[EvidenceItem, ...]:
        """Return deterministic evidence derived from sanitized exchanges."""
