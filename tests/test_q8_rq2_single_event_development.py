"""One-event Q8 prompt contract, synthetic-only, no model/holdout execution."""
from __future__ import annotations

import json

import pytest

from schemas.logging import ApplicationEventType
from schemas.rq2_dataset import RQ2ClassifierEvent
from services.q8_rq2_single_event_development import (
    PROMPT_SHA256,
    SINGLE_EVENT_PROMPT_VERSION,
    SYSTEM_PROMPT,
    Q8SingleEventBlocked,
    model_visible_event,
    normalize_event,
    render_chatml_prompt,
    validate_single_event_answer,
)

MODEL_SHA="51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304"


def event():
    return RQ2ClassifierEvent(
        schema_version="1.0",event_type=ApplicationEventType.VALIDATION_EVENT,
        component="synthetic_lab",route_name="training_search",
        method="GET",status_code=200,
        attributes={"outcome":"escaped","reflected_raw":False},error_type=None
    )


def answer(label="benign",confidence=0.6):
    return json.dumps({"classification":label,"confidence":confidence,
                       "reason":"Event explicitly reports a normal escaped response."})


def test_prompt_version_and_sha_are_stable():
    from hashlib import sha256
    assert SINGLE_EVENT_PROMPT_VERSION == "q8-rq2-single-event-v1-development"
    assert len(PROMPT_SHA256)==64 and sha256(SYSTEM_PROMPT.encode()).hexdigest()==PROMPT_SHA256
    assert "ONE normalized" in SYSTEM_PROMPT
    assert "unknown" in SYSTEM_PROMPT
    assert "Do not invent" in SYSTEM_PROMPT


def test_model_input_is_exact_original_frozen_event():
    original=event()
    visible=model_visible_event(original)
    assert visible==original.model_dump(mode="json")
    assert normalize_event(visible)==original
    assert set(visible)==set(RQ2ClassifierEvent.model_fields)
    assert "response_excerpt" not in visible and "observations" not in visible


def test_prompt_no_extra_baseline_or_ground_truth():
    payload=render_chatml_prompt(event())
    assert payload.count("<|im_start|>system")==1
    assert payload.count("<|im_start|>user")==1
    assert payload.count("<|im_start|>assistant")==1
    raw=payload.split("<|im_start|>user\n",1)[1].split("<|im_end|>",1)[0]
    assert json.loads(raw)==event().model_dump(mode="json")
    assert "ground_truth_label" not in raw
    assert "source_kind" not in raw
    assert "baseline_response" not in raw


@pytest.mark.parametrize("extra",[
    {"ground_truth_label":"benign"},
    {"expected":"benign"},
    {"response_excerpt":"invented"},
    {"observations":[]},
    {"source_test_id":"secret"},
    {"run_id":"trusted_run"},
])
def test_evaluator_or_http_pair_metadata_rejected(extra):
    raw=event().model_dump(mode="json")
    raw.update(extra)
    with pytest.raises(Q8SingleEventBlocked):
        render_chatml_prompt(raw)


@pytest.mark.parametrize("field",["schema_version","event_type","component",
 "route_name","method","status_code","attributes","error_type"])
def test_no_required_event_field_may_be_deleted(field):
    raw=event().model_dump(mode="json")
    del raw[field]
    with pytest.raises(Q8SingleEventBlocked,match="strict_M18_one_event_fields_required"):
        normalize_event(raw)


def test_original_event_not_mutated():
    obj=event()
    before=obj.model_dump_json()
    validate_single_event_answer(input_event=obj,raw_content=answer(),model_sha256=MODEL_SHA)
    assert obj.model_dump_json()==before


def test_valid_typed_answer_returns_non_authoritative_blue_triage():
    receipt=validate_single_event_answer(input_event=event(),raw_content=answer(),
                                         model_sha256=MODEL_SHA)
    assert receipt["decision"]["classification"]=="benign"
    assert receipt["preliminary_blue_action"]=="no_action"
    assert receipt["research_admitted"] is False
    assert receipt["registered_test_dispatched"] is False
    assert receipt["source_analysis_authorized"] is False
    assert receipt["patch_preparation_authorized"] is False


def test_model_attack_label_does_not_authorize_any_operation():
    receipt=validate_single_event_answer(input_event=event(),
        raw_content=answer("xss",0.96),model_sha256=MODEL_SHA)
    assert receipt["decision"]["classification"]=="xss"
    assert receipt["preliminary_blue_action"]=="select_registered_test"
    assert receipt["registered_test_dispatched"] is False
    assert receipt["source_analysis_authorized"] is False
    assert receipt["patch_preparation_authorized"] is False


@pytest.mark.parametrize("raw", [
    "not-json",
    "",
    "[]",
    "true",
    '{"classification":"xss","confidence":0.9,"reason":"X","run_test":true}',
    '{"classification":"xss","confidence":true,"reason":"X"}',
    '{"classification":"not_allowed","confidence":0.9,"reason":"X"}',
    '{"classification":"xss","confidence":2.0,"reason":"X"}',
    '{"classification":"xss","confidence":0.9,"reason":""}',
])
def test_invalid_or_action_smuggling_response_refused(raw):
    with pytest.raises(Q8SingleEventBlocked):
        validate_single_event_answer(input_event=event(),raw_content=raw,
                                     model_sha256=MODEL_SHA)


def test_unapproved_origin_or_weights_rejected():
    with pytest.raises(Q8SingleEventBlocked):
        validate_single_event_answer(input_event=event(),raw_content=answer(),
                                    model_sha256="0"*64)
    with pytest.raises(Q8SingleEventBlocked):
        validate_single_event_answer(input_event=event(),raw_content=answer(),
                                    model_sha256=MODEL_SHA,raw_origin="deterministic_policy")


def test_frozen_m18_schema_never_changed():
    assert "observations" not in RQ2ClassifierEvent.model_fields
    assert "response_excerpt" not in RQ2ClassifierEvent.model_fields
    assert set(model_visible_event(event()))==set(RQ2ClassifierEvent.model_fields)
