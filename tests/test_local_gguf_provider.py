"""Offline checks for the loopback-only Q6 structured provider."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from llm.interface import ProviderBindingError, validate_provider_binding
from llm.local_gguf_provider import LocalGgufDevelopmentProvider, LocalGgufProviderError
from llm.prompt_catalog import PromptCatalog
from schemas.common import AgentRole, ClassificationLabel
from schemas.experiment_results import TokenUsageStatus
from schemas.experiments import ModelConfiguration
from schemas.prompts import PromptAsset
from schemas.rq2_dataset import RQ2ClassificationDecision


class FakeResponse:
    status = 200

    def __init__(self, raw: bytes):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, _limit):
        return self.raw


def client(tmp_path: Path):
    model = tmp_path / "weights.gguf"
    model.write_bytes(b"synthetic-test-weights")
    import hashlib

    model_hash = hashlib.sha256(model.read_bytes()).hexdigest()
    evidence = tmp_path / "external"
    evidence.mkdir()
    config = ModelConfiguration(
        provider="llama_cpp",
        model_name="q6-specialist",
        temperature=0.0,
        max_output_tokens=256,
        seed=None,
    )
    prompts = PromptCatalog(
        (
            PromptAsset(
                prompt_id="triage-development",
                version="v1",
                role=AgentRole.BLUE_TRIAGE,
                system_prompt="Only classify the supplied synthetic event.",
            ),
        )
    )
    obj = LocalGgufDevelopmentProvider(
        model_path=model,
        expected_model_sha256=model_hash,
        configuration=config,
        prompts=prompts,
        evidence_dir=evidence,
        port=18080,
    )
    return obj, evidence, model


def response(content, usage=None, reason="stop"):
    return json.dumps(
        {"choices": [{"message": {"content": content}, "finish_reason": reason}], "usage": usage}
    ).encode()


def test_valid_structured_response_one_dispatch_and_hash_evidence(tmp_path):
    provider, evidence, _ = client(tmp_path)
    content = json.dumps(
        {"classification": "xss", "confidence": 0.97, "reason": "unsafe reflection"}
    )
    raw = response(content, {"prompt_tokens": 22, "completion_tokens": 13})
    with patch("llm.local_gguf_provider.urlopen", return_value=FakeResponse(raw)) as mock:
        result = provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE,
            input_data={"event_id": "safe-fixture"},
            response_model=RQ2ClassificationDecision,
        )
    assert result["classification"] == ClassificationLabel.XSS.value
    assert mock.call_count == 1
    request_bytes = (evidence / "call-000001-request.json").read_bytes()
    request = json.loads(request_bytes)
    receipt = json.loads((evidence / "call-000001-receipt.json").read_text())
    assert receipt["request_sha256"] == hashlib.sha256(request_bytes).hexdigest()
    assert (
        request_bytes
        == json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )
    assert request["messages"][1]["content"] == '{"event_id":"safe-fixture"}'
    assert request["stream"] is False
    assert request["response_format"]["type"] == "json_object"
    assert request["response_format"]["schema"] == RQ2ClassificationDecision.model_json_schema()
    assert request["response_format"]["schema"]["additionalProperties"] is False
    assert json.loads((evidence / "call-000001-receipt.json").read_text())["status"] == "COMPLETED"
    assert (evidence / "call-000001-response.raw").read_bytes() == raw
    usage = provider.take_last_usage()
    assert usage.input_tokens == 22 and usage.output_tokens == 13
    assert usage.token_usage_status == TokenUsageStatus.REPORTED
    assert provider.take_last_usage().input_tokens is None


@pytest.mark.parametrize(
    "bad",
    [
        response("not json"),
        response('{"classification":"xss","confidence":4,"reason":"wrong"}'),
        response('{"classification":"xss","confidence":0.8,"reason":"fine"}', reason="length"),
    ],
)
def test_malformed_or_incomplete_output_fails_closed_and_preserves_raw(tmp_path, bad):
    provider, evidence, _ = client(tmp_path)
    with (
        patch("llm.local_gguf_provider.urlopen", return_value=FakeResponse(bad)) as mock,
        pytest.raises(LocalGgufProviderError),
    ):
        provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE,
            input_data={"event_id": "safe-fixture"},
            response_model=RQ2ClassificationDecision,
        )
    assert mock.call_count == 1
    assert json.loads((evidence / "call-000001-receipt.json").read_text())["status"] == "FAILED"
    assert (evidence / "call-000001-response.raw").read_bytes() == bad
    assert provider.take_last_usage().token_usage_status == TokenUsageStatus.NOT_REPORTED


def test_transport_error_records_failure_with_no_fabricated_usage(tmp_path):
    provider, evidence, _ = client(tmp_path)
    with (
        patch(
            "llm.local_gguf_provider.urlopen", side_effect=TimeoutError("synthetic timeout")
        ) as mock,
        pytest.raises(LocalGgufProviderError),
    ):
        provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE,
            input_data={"event_id": "safe-fixture"},
            response_model=RQ2ClassificationDecision,
        )
    assert mock.call_count == 1
    assert (
        json.loads((evidence / "call-000001-receipt.json").read_text())["error_type"]
        == "TimeoutError"
    )
    assert (evidence / "call-000001-response.raw").read_bytes() == b""


def test_hash_drift_fails_before_network(tmp_path):
    provider, evidence, model = client(tmp_path)
    model.write_bytes(b"changed")
    with (
        patch("llm.local_gguf_provider.urlopen") as mock,
        pytest.raises(LocalGgufProviderError, match="pinned model changed"),
    ):
        provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE, input_data={}, response_model=RQ2ClassificationDecision
        )
    mock.assert_not_called()
    assert not list(evidence.iterdir())


def test_cannot_claim_final_capable_without_live_process_attestation(tmp_path):
    provider, _, _ = client(tmp_path)
    assert provider.descriptor.final_capable is False
    assert provider.descriptor.identity_verified is False
    with pytest.raises(ProviderBindingError):
        validate_provider_binding(
            provider=provider,
            expected=provider.configuration,
            require_final_capable=True,
        )


def test_wrong_model_hash_is_rejected(tmp_path):
    model = tmp_path / "other.gguf"
    model.write_bytes(b"simulated")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(ValueError, match="model hash"):
        LocalGgufDevelopmentProvider(
            model_path=model,
            expected_model_sha256="a" * 64,
            configuration=ModelConfiguration(provider="llama_cpp", model_name="q6-specialist"),
            prompts=PromptCatalog(
                (
                    PromptAsset(
                        prompt_id="triage",
                        version="v1",
                        role=AgentRole.BLUE_TRIAGE,
                        system_prompt="Safe system prompt",
                    ),
                )
            ),
            evidence_dir=evidence,
        )


def test_refuse_symlink_aliases_before_using_file_or_evidence_dir(tmp_path):
    valid, evidence, model = client(tmp_path)
    link_model = tmp_path / "model-link.gguf"
    link_model.symlink_to(model)
    with pytest.raises(ValueError, match="symlinks"):
        LocalGgufDevelopmentProvider(
            model_path=link_model,
            expected_model_sha256=valid.model_sha256,
            configuration=valid.configuration,
            prompts=valid.prompts,
            evidence_dir=evidence,
        )

    link_evidence = tmp_path / "evidence-link"
    link_evidence.symlink_to(evidence, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        LocalGgufDevelopmentProvider(
            model_path=model,
            expected_model_sha256=valid.model_sha256,
            configuration=valid.configuration,
            prompts=valid.prompts,
            evidence_dir=link_evidence,
        )


def test_rejected_extra_keys_retains_real_usage_and_never_coerces_output(tmp_path):
    provider, evidence, _ = client(tmp_path)
    invalid = json.dumps({
        "classification": "sql_injection",
        "confidence": 0.91,
        "reason": "test synthetic event",
        "case": "forbidden-extra-key",
    })
    raw = response(invalid, {"prompt_tokens": 37, "completion_tokens": 18})
    with (
        patch("llm.local_gguf_provider.urlopen", return_value=FakeResponse(raw)) as mock,
        pytest.raises(LocalGgufProviderError),
    ):
        provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE,
            input_data={"event_id": "safe-fixture"},
            response_model=RQ2ClassificationDecision,
        )
    assert mock.call_count == 1
    receipt = json.loads((evidence / "call-000001-receipt.json").read_text())
    assert receipt["status"] == "FAILED"
    assert receipt["error_type"] == "ValidationError"
    assert receipt["usage"]["input_tokens"] == 37
    assert receipt["usage"]["output_tokens"] == 18
    assert receipt["usage"]["token_usage_status"] == "reported"
    assert (evidence / "call-000001-response.raw").read_bytes() == raw
    usage = provider.take_last_usage()
    assert (usage.input_tokens, usage.output_tokens) == (37, 18)
    assert usage.token_usage_status == TokenUsageStatus.REPORTED


def test_incomplete_completion_preserves_reported_token_usage(tmp_path):
    provider, evidence, _ = client(tmp_path)
    raw = response('{"classification":"benign","confidence":0.95,"reason":"no danger"}',
                   {"prompt_tokens": 12, "completion_tokens": 7}, reason="length")
    with (
        patch("llm.local_gguf_provider.urlopen", return_value=FakeResponse(raw)),
        pytest.raises(LocalGgufProviderError),
    ):
        provider.generate_structured(
            role=AgentRole.BLUE_TRIAGE,
            input_data={"event_id": "safe-fixture"},
            response_model=RQ2ClassificationDecision,
        )
    receipt = json.loads((evidence / "call-000001-receipt.json").read_text())
    assert receipt["status"] == "FAILED"
    assert receipt["usage"]["token_usage_status"] == "reported"
    usage = provider.take_last_usage()
    assert (usage.input_tokens, usage.output_tokens) == (12, 7)
