"""Deterministic no-network structured provider used by milestone verification."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from pydantic import BaseModel

from schemas.blue_team import (
    CodeFinding,
    MonitoringResult,
    SourceReadResult,
    SourceSnippet,
    TriageResult,
)
from schemas.common import AgentRole, ClassificationLabel
from schemas.patches import PatchProposal
from schemas.logging import LogReadResult
from schemas.red_team import (
    AttackPlan,
    AttackPlanningCatalog,
    AttackVerification,
    ReconnaissanceResult,
    RestrictedReconnaissanceContext,
    TestExecutionResult,
)


class MockProviderError(RuntimeError):
    """Raised when a deterministic mock fixture cannot satisfy a request."""


class MockProvider:
    """Produce deterministic typed Red/Blue responses without external I/O."""

    def __init__(
        self,
        *,
        planned_test_id: str | None = None,
        blue_classification: ClassificationLabel | None = None,
        blue_confidence: float = 1.0,
        include_generated_patch_test: bool = False,
    ) -> None:
        self.planned_test_id = planned_test_id
        self.blue_classification = blue_classification
        self.blue_confidence = blue_confidence
        self.include_generated_patch_test = include_generated_patch_test
        self._call_roles: list[AgentRole] = []

    @property
    def call_roles(self) -> tuple[AgentRole, ...]:
        """Return provider-call roles in deterministic invocation order."""
        return tuple(self._call_roles)

    def generate_structured(
        self,
        *,
        role: AgentRole,
        input_data: Mapping[str, Any],
        response_model: type[BaseModel],
    ) -> Mapping[str, Any]:
        self._call_roles.append(role)

        if role == AgentRole.RED_RECONNAISSANCE:
            if response_model is not ReconnaissanceResult:
                raise MockProviderError("unexpected reconnaissance response model")
            return self._reconnaissance(input_data)

        if role == AgentRole.RED_ATTACK_PLANNER:
            if response_model is not AttackPlan:
                raise MockProviderError("unexpected attack-planning response model")
            return self._attack_plan(input_data)

        if role == AgentRole.RED_ATTACK_VERIFIER:
            if response_model is not AttackVerification:
                raise MockProviderError("unexpected verification response model")
            return self._attack_verification(input_data)

        if role == AgentRole.BLUE_MONITORING:
            if response_model is not MonitoringResult:
                raise MockProviderError("unexpected monitoring response model")
            return self._monitoring(input_data)

        if role == AgentRole.BLUE_TRIAGE:
            if response_model is not TriageResult:
                raise MockProviderError("unexpected triage response model")
            return self._triage(input_data)

        if role == AgentRole.BLUE_CODE_ANALYSIS:
            if response_model is not CodeFinding:
                raise MockProviderError("unexpected code-analysis response model")
            return self._code_analysis(input_data)

        if role == AgentRole.BLUE_PATCH_GENERATION:
            if response_model is not PatchProposal:
                raise MockProviderError("unexpected patch-generation response model")
            return self._patch_generation(input_data)

        raise MockProviderError(f"unsupported mock agent role: {role.value}")

    @staticmethod
    def _reconnaissance(input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        context = RestrictedReconnaissanceContext.model_validate(input_data)
        return {
            "target_id": context.target_id,
            "candidate_endpoints": [
                endpoint.model_dump(mode="json")
                for endpoint in context.endpoints
            ],
            "rationale": (
                "Describe only the approved registered endpoint surface supplied "
                "by the trusted reconnaissance service."
            ),
        }

    def _attack_plan(self, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.planned_test_id is None:
            raise MockProviderError("planned_test_id is required for Red attack planning")

        reconnaissance = ReconnaissanceResult.model_validate(
            input_data.get("reconnaissance")
        )
        catalog = AttackPlanningCatalog.model_validate(
            input_data.get("planning_catalog")
        )

        option = next(
            (
                item
                for item in catalog.options
                if item.test_id == self.planned_test_id
            ),
            None,
        )
        if option is None:
            raise MockProviderError(
                f"planned test {self.planned_test_id!r} is not in the restricted catalog"
            )

        if not any(
            endpoint.endpoint_id == option.endpoint_id
            for endpoint in reconnaissance.candidate_endpoints
        ):
            raise MockProviderError(
                "planned test endpoint was not present in reconnaissance output"
            )

        return {
            "target_id": catalog.target_id,
            "test_id": option.test_id,
            "endpoint_id": option.endpoint_id,
            "vulnerability_class": option.vulnerability_class.value,
            "parameter_choices": {},
            "rationale": (
                "Select the configured deterministic registered test from the "
                "restricted planning catalog."
            ),
        }

    @staticmethod
    def _attack_verification(
        input_data: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        plan = AttackPlan.model_validate(input_data.get("attack_plan"))
        execution = TestExecutionResult.model_validate(
            input_data.get("execution_result")
        )

        confirmed = (
            execution.completed
            and not execution.timed_out
            and bool(execution.evidence)
        )
        evidence_ids = (
            [item.evidence_id for item in execution.evidence]
            if confirmed
            else []
        )

        return {
            "target_id": plan.target_id,
            "test_id": plan.test_id,
            "confirmed": confirmed,
            "confidence": 1.0,
            "evidence_ids": evidence_ids,
            "reason": (
                "Structured deterministic executor evidence supports the planned test."
                if confirmed
                else "Deterministic execution did not produce confirmable evidence."
            ),
        }

    def _monitoring(self, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        logs = LogReadResult.model_validate(input_data.get("logs"))
        event_ids = [event.event_id for event in logs.events]
        suspicious = (
            self.blue_classification
            in {
                ClassificationLabel.SQL_INJECTION,
                ClassificationLabel.XSS,
                ClassificationLabel.PATH_TRAVERSAL,
            }
        )
        return {
            "run_id": logs.run_id,
            "event_ids": event_ids,
            "suspicious_event_ids": event_ids if suspicious else [],
            "summary": "Deterministic mock monitoring fixture over supplied normalized events.",
        }

    def _triage(self, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        logs = LogReadResult.model_validate(input_data.get("logs"))
        allowed_labels = {
            ClassificationLabel(value)
            for value in input_data.get("allowed_labels", [])
        }
        if allowed_labels != set(ClassificationLabel):
            raise MockProviderError("triage input did not contain the frozen label set")

        classification = self.blue_classification
        if classification is None and input_data.get("rule_result") is not None:
            classification = TriageResult.model_validate(
                input_data.get("rule_result")
            ).classification
        if classification is None:
            classification = ClassificationLabel.UNKNOWN

        suspicious = classification in {
            ClassificationLabel.SQL_INJECTION,
            ClassificationLabel.XSS,
            ClassificationLabel.PATH_TRAVERSAL,
        }
        supporting_ids = (
            [event.event_id for event in logs.events]
            if suspicious
            else []
        )
        return {
            "run_id": logs.run_id,
            "is_suspicious": suspicious,
            "classification": classification.value,
            "confidence": self.blue_confidence,
            "supporting_event_ids": supporting_ids,
            "reason": "Deterministic mock triage fixture over the supplied normalized evidence.",
        }

    @classmethod
    def _code_analysis(cls, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        triage = TriageResult.model_validate(input_data.get("triage"))
        source_context = SourceReadResult.model_validate(
            input_data.get("source_context")
        )

        anchors: dict[ClassificationLabel, tuple[str, ...]] = {
            ClassificationLabel.SQL_INJECTION: (
                "WHERE username =",
                "session.execute(text(query))",
            ),
            ClassificationLabel.XSS: (
                'Search term: {q}',
                "HTMLResponse(content=body)",
            ),
            ClassificationLabel.PATH_TRAVERSAL: (
                "intended_public_root / path",
                "candidate.read_text",
            ),
        }
        root_causes: dict[ClassificationLabel, str] = {
            ClassificationLabel.SQL_INJECTION: (
                "Caller-controlled login input is interpolated into SQL text before execution."
            ),
            ClassificationLabel.XSS: (
                "Caller-controlled search input is inserted into HTML without output escaping."
            ),
            ClassificationLabel.PATH_TRAVERSAL: (
                "Caller-controlled path input is resolved relative to the public directory "
                "without enforcing containment within that intended public root."
            ),
        }

        try:
            expected_anchors = anchors[triage.classification]
            root_cause = root_causes[triage.classification]
        except KeyError as exc:
            raise MockProviderError(
                "code-analysis mock requires a supported vulnerability classification"
            ) from exc

        for snippet in source_context.snippets:
            match = cls._find_anchor(snippet, expected_anchors)
            if match is None:
                continue
            line_number, function_name = match
            return {
                "run_id": triage.run_id,
                "file_path": snippet.file_path,
                "function_or_route": function_name,
                "root_cause": root_cause,
                "supporting_lines": [
                    {"start_line": line_number, "end_line": line_number}
                ],
                "confidence": 1.0,
            }

        raise MockProviderError(
            "supplied source snippets did not contain a matching code-analysis anchor"
        )

    @staticmethod
    def _find_anchor(
        snippet: SourceSnippet,
        anchors: tuple[str, ...],
    ) -> tuple[int, str] | None:
        function_name = "unknown_function"
        function_pattern = re.compile(
            r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
        )
        for offset, line in enumerate(snippet.content.splitlines()):
            function_match = function_pattern.match(line)
            if function_match is not None:
                function_name = function_match.group(1)
            if any(anchor in line for anchor in anchors):
                return snippet.start_line + offset, function_name
        return None

    def _patch_generation(self, input_data: Mapping[str, Any]) -> Mapping[str, Any]:
        triage = TriageResult.model_validate(input_data.get("triage"))
        finding = CodeFinding.model_validate(input_data.get("code_finding"))
        source_context = SourceReadResult.model_validate(input_data.get("source_context"))
        attempt_number = int(input_data.get("attempt_number"))
        constraints = input_data.get("patch_constraints")
        if not isinstance(constraints, Mapping):
            raise MockProviderError("patch generation requires deterministic patch constraints")
        if constraints.get("allowed_source_file") != finding.file_path:
            raise MockProviderError("patch constraint does not match supplied CodeFinding")

        supplied = "\n".join(snippet.content for snippet in source_context.snippets)
        changes: list[dict[str, Any]] = []

        if triage.classification == ClassificationLabel.SQL_INJECTION:
            original = '''        query = (
            "SELECT username, display_name FROM users "
            f"WHERE username = '{payload.username}' "
            f"AND password_hash = '{password_hash}' "
            "LIMIT 1"
        )

        row = session.execute(text(query)).mappings().first()'''
            replacement = '''        query = text(
            "SELECT username, display_name FROM users "
            "WHERE username = :username "
            "AND password_hash = :password_hash "
            "LIMIT 1"
        )

        row = session.execute(
            query,
            {"username": payload.username, "password_hash": password_hash},
        ).mappings().first()'''
            changes.append(
                self._grounded_change(
                    supplied=supplied,
                    file_path=finding.file_path,
                    original=original,
                    replacement=replacement,
                    rationale="Use bound SQL parameters instead of interpolating caller-controlled input.",
                )
            )
        elif triage.classification == ClassificationLabel.XSS:
            changes.extend(
                [
                    self._grounded_change(
                        supplied=supplied,
                        file_path=finding.file_path,
                        original="from pathlib import Path",
                        replacement="from html import escape\nfrom pathlib import Path",
                        rationale="Import the standard-library HTML escaping helper.",
                    ),
                    self._grounded_change(
                        supplied=supplied,
                        file_path=finding.file_path,
                        original='            f"<p id=\\"result\\">Search term: {q}</p>"',
                        replacement='            f"<p id=\\"result\\">Search term: {escape(q)}</p>"',
                        rationale="Escape reflected caller-controlled text before inserting it into HTML.",
                    ),
                ]
            )
        elif triage.classification == ClassificationLabel.PATH_TRAVERSAL:
            original = '''        candidate = (intended_public_root / path).resolve(strict=False)

        # SAFETY BOUNDARY: the educational traversal cannot escape the isolated
        # synthetic scenario directory into the project or host filesystem.
        try:
            candidate.relative_to(scenario_root)
        except ValueError as exc:
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": path, "outcome": "sandbox_blocked"},
                status_code=403,
            )
            raise HTTPException(
                status_code=403,
                detail="Scenario sandbox escape blocked",
            ) from exc

        if not candidate.is_file():'''
            replacement = '''        candidate = (intended_public_root / path).resolve(strict=False)

        # SAFETY BOUNDARY: the educational traversal cannot escape the isolated
        # synthetic scenario directory into the project or host filesystem.
        try:
            candidate.relative_to(scenario_root)
        except ValueError as exc:
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": path, "outcome": "sandbox_blocked"},
                status_code=403,
            )
            raise HTTPException(
                status_code=403,
                detail="Scenario sandbox escape blocked",
            ) from exc

        try:
            candidate.relative_to(intended_public_root)
        except ValueError as exc:
            emit_structured_event(
                event_type=ApplicationEventType.FILE_ACCESS_EVENT,
                attributes={"requested_path": path, "outcome": "public_root_blocked"},
                status_code=403,
            )
            raise HTTPException(status_code=403, detail="Path traversal blocked") from exc

        if not candidate.is_file():'''
            changes.append(
                self._grounded_change(
                    supplied=supplied,
                    file_path=finding.file_path,
                    original=original,
                    replacement=replacement,
                    rationale="Enforce containment within the intended public directory before file access.",
                )
            )
        else:
            raise MockProviderError("patch mock requires a supported vulnerability classification")

        proposed_test = None
        if self.include_generated_patch_test:
            test_name = {
                ClassificationLabel.SQL_INJECTION: "test_generated_sqli_remediation",
                ClassificationLabel.XSS: "test_generated_xss_remediation",
                ClassificationLabel.PATH_TRAVERSAL: "test_generated_path_traversal_remediation",
            }[triage.classification]
            proposed_test = {
                "test_name": test_name,
                "target_file": finding.file_path,
                "purpose": "Record a bounded generated security-test proposal for later verification milestones.",
                "proposed_test_content": (
                    '\"\"\"Generated security-test proposal; execution belongs to a later milestone.\"\"\"\n\n'
                    f'def {test_name}():\n'
                    '    assert True\n'
                ),
            }

        return {
            "run_id": triage.run_id,
            "target_id": source_context.target_id,
            "attempt_number": attempt_number,
            "changes": changes,
            "security_rationale": "Apply a minimal grounded remediation to the localized vulnerable source.",
            "expected_effect": "The localized vulnerability should be removed without broad source changes.",
            "regression_risks": ["Behavior must be verified in the later deterministic verification pipeline."],
            "proposed_security_test": proposed_test,
        }

    @staticmethod
    def _grounded_change(
        *,
        supplied: str,
        file_path: str,
        original: str,
        replacement: str,
        rationale: str,
    ) -> dict[str, Any]:
        if original not in supplied:
            raise MockProviderError("required patch anchor was absent from supplied source context")
        return {
            "file_path": file_path,
            "original_content": original,
            "replacement_content": replacement,
            "rationale": rationale,
        }
