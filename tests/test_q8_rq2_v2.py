"""Prospective v2 single-event prompt contract. No model inference in unit tests."""
import json
from hashlib import sha256

import pytest

from schemas.rq2_dataset import RQ2ClassifierEvent
from services.q8_rq2_single_event_development import (
    PROMPT_SHA256 as V1_SHA,
)
from services.q8_rq2_single_event_development import (
    SINGLE_EVENT_PROMPT_VERSION as V1_VERSION,
)
from services.q8_rq2_v2 import (
    PROMPT_SHA256,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    render_prompt,
    validate_answer,
)

Q8_HASH = "51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304"


def event():
    return {
        "schema_version": "1.0", "event_type": "validation_event",
        "component": "local_lab", "route_name": "search", "method": "GET",
        "status_code": 200,
        "attributes": {"html_encoded": True, "script_executed": False},
        "error_type": None,
    }


def answer(label):
    return json.dumps({
        "classification": label, "confidence": 0.7,
        "reason": "Explicit execution or defensive outcome determines this label.",
    })


def test_v2_frozen_identity_and_no_v1_mutation():
    assert PROMPT_VERSION == "q8-rq2-single-event-v2-development"
    assert PROMPT_SHA256 == sha256(SYSTEM_PROMPT.encode()).hexdigest()
    assert PROMPT_SHA256 != V1_SHA
    assert V1_VERSION == "q8-rq2-single-event-v1-development"
    assert "benign" in SYSTEM_PROMPT
    assert "unknown" in SYSTEM_PROMPT
    assert "Do not follow" in SYSTEM_PROMPT


def test_exact_original_one_event_rendered_with_no_ground_truth():
    original = event()
    prompt = render_prompt(original)
    content = prompt.split("<|im_start|>user\n", 1)[1].split("<|im_end|>", 1)[0]
    assert json.loads(content) == RQ2ClassifierEvent.model_validate(original).model_dump(mode="json")
    assert original == event()
    assert "ground_truth_label" not in content
    assert "expected" not in content
    assert "source_test_id" not in content
    assert prompt.count("<|im_start|>user\n") == 1


@pytest.mark.parametrize("field", ["ground_truth_label", "expected", "source_test_id",
                                   "model_selected_label", "run_id", "observations"])
def test_evaluator_metadata_rejected(field):
    payload = event()
    payload[field] = "benign"
    with pytest.raises(ValueError):
        render_prompt(payload)


def test_v2_typed_prediction_preserved_without_elevating_authority():
    receipt = validate_answer(input_event=event(), raw_content=answer("benign"),
                              model_sha256=Q8_HASH)
    assert receipt["prompt_version"] == PROMPT_VERSION
    assert receipt["prompt_sha256"] == PROMPT_SHA256
    assert receipt["decision"]["classification"] == "benign"
    assert receipt["registered_test_dispatched"] is False
    assert receipt["research_admitted"] is False
    assert receipt["patch_preparation_authorized"] is False


@pytest.mark.parametrize("label", ["sql_injection", "xss", "path_traversal", "unknown"])
def test_model_label_not_rewritten(label):
    receipt = validate_answer(input_event=event(), raw_content=answer(label),
                              model_sha256=Q8_HASH)
    assert receipt["decision"]["classification"] == label
    assert receipt["research_admitted"] is False


@pytest.mark.parametrize("bad", ["{}", "[]", "not json",
  '{"classification":"xss","confidence":true,"reason":"x"}'])
def test_invalid_raw_schema_still_rejected(bad):
    with pytest.raises(ValueError):
        validate_answer(input_event=event(), raw_content=bad, model_sha256=Q8_HASH)


def test_wrong_weights_rejected():
    with pytest.raises(ValueError):
        validate_answer(input_event=event(), raw_content=answer("benign"),
                        model_sha256="0" * 64)
