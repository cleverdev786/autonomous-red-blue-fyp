"""Deterministic rule-only vulnerability classification baseline for RQ2."""

from __future__ import annotations

from collections import defaultdict
from html import unescape
import re
from urllib.parse import unquote

from schemas.blue_team import TriageResult
from schemas.common import ClassificationLabel
from schemas.logging import ApplicationLogEvent, LogReadResult


_SQL_BOOLEAN_PATTERN = re.compile(
    r"(?:['\"]\s*)?\b(?:or|and)\b\s+"
    r"(?:['\"]?[^\s'\"]+['\"]?|\d+)\s*=\s*"
    r"(?:['\"]?[^\s'\"]+['\"]?|\d+)",
    re.IGNORECASE,
)
_SQL_UNION_PATTERN = re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)
_SQL_COMMENT_PATTERN = re.compile(r"(?:--(?:\s|$)|/\*|#(?:\s|$))")

_XSS_SCRIPT_PATTERN = re.compile(r"<\s*script\b", re.IGNORECASE)
_XSS_EVENT_HANDLER_PATTERN = re.compile(
    r"(?:<[^>]*\s|\s)on[a-z][a-z0-9_-]*\s*=",
    re.IGNORECASE,
)
_XSS_JAVASCRIPT_URI_PATTERN = re.compile(r"\bjavascript\s*:", re.IGNORECASE)

_PATH_ATTRIBUTE_TOKENS = ("path", "file", "filename", "filepath")


class RuleEngineInputError(ValueError):
    """Raised when normalized input violates the run-isolation contract."""


class RuleEngine:
    """Classify normalized application observations without any model call."""

    def classify(self, logs: LogReadResult) -> TriageResult:
        """Return one deterministic triage result for a normalized run."""
        self._validate_run_integrity(logs)

        if not logs.events:
            return TriageResult(
                run_id=logs.run_id,
                is_suspicious=False,
                classification=ClassificationLabel.UNKNOWN,
                confidence=0.0,
                supporting_event_ids=(),
                reason="No normalized application events were available for classification.",
            )

        findings: dict[ClassificationLabel, set[str]] = defaultdict(set)

        for event in logs.events:
            if self._matches_sql_injection(event):
                findings[ClassificationLabel.SQL_INJECTION].add(event.event_id)
            if self._matches_xss(event):
                findings[ClassificationLabel.XSS].add(event.event_id)
            if self._matches_path_traversal(event):
                findings[ClassificationLabel.PATH_TRAVERSAL].add(event.event_id)

        matched_labels = tuple(sorted(findings, key=lambda item: item.value))
        if not matched_labels:
            return TriageResult(
                run_id=logs.run_id,
                is_suspicious=False,
                classification=ClassificationLabel.BENIGN,
                confidence=1.0,
                supporting_event_ids=(),
                reason="No deterministic vulnerability signature was observed.",
            )

        if len(matched_labels) > 1:
            supporting_ids = self._sorted_supporting_ids(findings)
            return TriageResult(
                run_id=logs.run_id,
                is_suspicious=True,
                classification=ClassificationLabel.UNKNOWN,
                confidence=0.0,
                supporting_event_ids=supporting_ids,
                reason=(
                    "Conflicting deterministic vulnerability signatures were observed; "
                    "the rule-only baseline does not apply class precedence."
                ),
            )

        classification = matched_labels[0]
        return TriageResult(
            run_id=logs.run_id,
            is_suspicious=True,
            classification=classification,
            confidence=1.0,
            supporting_event_ids=tuple(sorted(findings[classification])),
            reason=(
                "Deterministic observable input signatures support the "
                f"{classification.value} classification."
            ),
        )

    @staticmethod
    def _validate_run_integrity(logs: LogReadResult) -> None:
        mismatched = tuple(
            event.event_id for event in logs.events if event.run_id != logs.run_id
        )
        if mismatched:
            raise RuleEngineInputError(
                "normalized events must all match LogReadResult.run_id"
            )

    @staticmethod
    def _string_attributes(event: ApplicationLogEvent) -> tuple[tuple[str, str], ...]:
        return tuple(
            (key, value)
            for key, value in event.attributes.items()
            if isinstance(value, str)
        )

    @classmethod
    def _matches_sql_injection(cls, event: ApplicationLogEvent) -> bool:
        for _, value in cls._string_attributes(event):
            normalized = cls._decode_text(value)
            has_boolean_expression = _SQL_BOOLEAN_PATTERN.search(normalized) is not None
            has_union_select = _SQL_UNION_PATTERN.search(normalized) is not None
            has_sql_comment = _SQL_COMMENT_PATTERN.search(normalized) is not None
            if has_union_select or (has_boolean_expression and has_sql_comment):
                return True
        return False

    @classmethod
    def _matches_xss(cls, event: ApplicationLogEvent) -> bool:
        for _, value in cls._string_attributes(event):
            normalized = unescape(cls._decode_text(value))
            if (
                _XSS_SCRIPT_PATTERN.search(normalized)
                or _XSS_EVENT_HANDLER_PATTERN.search(normalized)
                or _XSS_JAVASCRIPT_URI_PATTERN.search(normalized)
            ):
                return True
        return False

    @classmethod
    def _matches_path_traversal(cls, event: ApplicationLogEvent) -> bool:
        for key, value in cls._string_attributes(event):
            lowered_key = key.lower()
            if not any(token in lowered_key for token in _PATH_ATTRIBUTE_TOKENS):
                continue

            normalized = cls._decode_text(value).replace("\\", "/")
            if any(segment == ".." for segment in normalized.split("/")):
                return True
        return False

    @staticmethod
    def _decode_text(value: str) -> str:
        decoded = value
        for _ in range(2):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        return decoded

    @staticmethod
    def _sorted_supporting_ids(
        findings: dict[ClassificationLabel, set[str]],
    ) -> tuple[str, ...]:
        return tuple(sorted({event_id for ids in findings.values() for event_id in ids}))
