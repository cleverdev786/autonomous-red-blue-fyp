"""Controlled SQL-injection evidence template for the local dummy login."""

from __future__ import annotations

import json

from schemas.common import HttpMethod
from schemas.red_team import EvidenceItem, HttpExchangeEvidence
from security_tests.base import RegisteredSecurityTest, RequestStep


class SqlInjectionLoginBypassTest(RegisteredSecurityTest):
    test_id = "sqli-login-bypass-001"

    def build_steps(self) -> tuple[RequestStep, ...]:
        return (
            RequestStep(
                step_id="control-wrong-password",
                endpoint_id="scenario-sqli-login",
                method=HttpMethod.POST,
                json_body={
                    "username": "student1",
                    "password": "definitely-wrong",
                },
            ),
            RequestStep(
                step_id="injection-bypass",
                endpoint_id="scenario-sqli-login",
                method=HttpMethod.POST,
                json_body={
                    "username": "' OR 1=1 --",
                    "password": "definitely-wrong",
                },
            ),
        )

    def evaluate(
        self,
        exchanges: tuple[HttpExchangeEvidence, ...],
    ) -> tuple[EvidenceItem, ...]:
        if len(exchanges) != 2:
            return ()

        control, attack = exchanges
        if control.status_code != 401 or attack.status_code != 200:
            return ()

        try:
            payload = json.loads(attack.body_excerpt)
        except json.JSONDecodeError:
            return ()

        if payload.get("authenticated") is not True:
            return ()

        return (
            EvidenceItem(
                evidence_id="sqli-auth-bypass-observed",
                evidence_type="authentication_bypass",
                summary=(
                    "The registered control request was rejected, while the "
                    "registered SQL-injection request authenticated with the "
                    "same incorrect password."
                ),
            ),
        )
