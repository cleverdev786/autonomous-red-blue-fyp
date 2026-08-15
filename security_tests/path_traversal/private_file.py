"""Bounded path-traversal evidence template for the synthetic file sandbox."""

from __future__ import annotations

from schemas.common import HttpMethod
from schemas.red_team import EvidenceItem, HttpExchangeEvidence
from security_tests.base import RegisteredSecurityTest, RequestStep


_SECRET_MARKER = "FYP_SCENARIO_SECRET=synthetic-traversal-evidence-only"


class PathTraversalPrivateFileTest(RegisteredSecurityTest):
    test_id = "path-traversal-private-file-001"

    def build_steps(self) -> tuple[RequestStep, ...]:
        return (
            RequestStep(
                step_id="control-public-file",
                endpoint_id="scenario-path-traversal-read",
                method=HttpMethod.GET,
                query_params={"path": "guide.txt"},
            ),
            RequestStep(
                step_id="traversal-private-file",
                endpoint_id="scenario-path-traversal-read",
                method=HttpMethod.GET,
                query_params={"path": "../private/demo-secret.txt"},
            ),
        )

    def evaluate(
        self,
        exchanges: tuple[HttpExchangeEvidence, ...],
    ) -> tuple[EvidenceItem, ...]:
        if len(exchanges) != 2:
            return ()

        control, attack = exchanges
        if control.status_code != 200 or attack.status_code != 200:
            return ()
        if "Public scenario guide" not in control.body_excerpt:
            return ()
        if _SECRET_MARKER not in attack.body_excerpt:
            return ()

        return (
            EvidenceItem(
                evidence_id="path-traversal-private-file-observed",
                evidence_type="synthetic_private_file_read",
                summary=(
                    "The registered traversal path reached the synthetic "
                    "private scenario file outside the intended public folder."
                ),
            ),
        )
