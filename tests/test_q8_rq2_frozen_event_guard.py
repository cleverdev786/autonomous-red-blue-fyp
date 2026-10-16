"""Regression barrier between M18 frozen RQ2 v1 and Q8/C12 paired-HTTP input.

These tests use only novel hand-authored synthetic application events, never
the protected 60-event evaluator dataset or ground truth.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from schemas.logging import ApplicationEventType
from schemas.rq2_dataset import (
    RQ2ClassificationDecision,
    RQ2ClassifierEvent,
    RQ2DatasetInputItem,
)
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked,
    classification_request,
    refuse_single_rq2_event,
)


def _event() -> RQ2ClassifierEvent:
    return RQ2ClassifierEvent(
        schema_version="1.0",
        event_type=ApplicationEventType.HTTP_REQUEST,
        component="synthetic_lab",
        route_name="safe_search",
        method="GET",
        status_code=200,
        attributes={"query_length": 7, "outcome": "normal"},
    )


def test_frozen_rq2_event_is_single_event_not_http_pair():
    event = _event()
    obj = event.model_dump(mode="json")
    assert set(obj) == {
        "schema_version", "event_type", "component", "route_name",
        "method", "status_code", "attributes", "error_type",
    }
    assert "response_excerpt" not in obj
    assert "observations" not in obj
    assert "baseline_response" not in obj
    assert "ground_truth_label" not in obj


def test_original_single_event_cannot_be_autoconverted_to_q8():
    event = _event()
    snapshot = event.model_dump_json()
    with pytest.raises(Q8DevelopmentBlocked, match="rq2_single_event_not_equivalent"):
        refuse_single_rq2_event(event)
    with pytest.raises(Q8DevelopmentBlocked):
        classification_request(event.model_dump(mode="json"))
    assert event.model_dump_json() == snapshot


def test_rq2_dataset_input_schema_must_remain_unchanged():
    item = RQ2DatasetInputItem(
        event_id="synthetic_dev_01",
        classifier_input_sha256="a" * 64,
        semantic_input_sha256="b" * 64,
        normalized_event=_event(),
    )
    assert "normalized_event" in item.model_dump()
    assert "observations" not in item.model_dump()
    with pytest.raises(ValidationError):
        RQ2DatasetInputItem.model_validate({
            **item.model_dump(mode="json"),
            "pair_from_other_event": {"observations": []},
        })


def test_attacker_cannot_smuggle_observations_into_rq2_frozen_event():
    raw = _event().model_dump(mode="json")
    raw["response_excerpt"] = "<h1>private detail</h1>"
    with pytest.raises(ValidationError):
        RQ2ClassifierEvent.model_validate(raw)


def test_original_output_label_contract_still_accepts_unknown():
    original = RQ2ClassificationDecision(
        classification="unknown",
        confidence=0.0,
        reason="Missing evidence from the single normalized event.",
    )
    assert original.classification.value == "unknown"


def test_two_observation_development_input_cannot_contain_evaluator_truth():
    paired = {
        "route": "/xss/search",
        "observations": [
            {"method": "GET", "parameters": {"q": "notes"},
             "status_code": 200, "response_excerpt": "<p>notes</p>"},
            {"method": "GET", "parameters": {"q": "chapter"},
             "status_code": 200, "response_excerpt": "<p>chapter</p>"},
        ],
    }
    req = classification_request(paired)
    assert req["role"] == "classification"
    assert len(req["input"]["observations"]) == 2
    assert "ground_truth" not in json.dumps(req)
    with pytest.raises(Q8DevelopmentBlocked):
        classification_request({**paired, "expected": "benign"})
