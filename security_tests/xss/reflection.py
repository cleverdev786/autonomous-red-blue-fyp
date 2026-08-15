"""Controlled reflected-XSS evidence template for the local dummy search."""

from __future__ import annotations

from schemas.common import HttpMethod
from schemas.red_team import EvidenceItem, HttpExchangeEvidence
from security_tests.base import RegisteredSecurityTest, RequestStep


_XSS_MARKER = "<script>fyp_xss_marker()</script>"


class XssReflectionTest(RegisteredSecurityTest):
    test_id = "xss-reflection-001"

    def build_steps(self) -> tuple[RequestStep, ...]:
        return (
            RequestStep(
                step_id="control-normal-search",
                endpoint_id="scenario-xss-search",
                method=HttpMethod.GET,
                query_params={"q": "notebook"},
            ),
            RequestStep(
                step_id="unescaped-reflection",
                endpoint_id="scenario-xss-search",
                method=HttpMethod.GET,
                query_params={"q": _XSS_MARKER},
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
        if "Search term: notebook" not in control.body_excerpt:
            return ()
        if _XSS_MARKER not in attack.body_excerpt:
            return ()

        return (
            EvidenceItem(
                evidence_id="xss-unescaped-reflection-observed",
                evidence_type="unescaped_html_reflection",
                summary=(
                    "The registered synthetic script marker was returned "
                    "unescaped in the scenario HTML response."
                ),
            ),
        )
