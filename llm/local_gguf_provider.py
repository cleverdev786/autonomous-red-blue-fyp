"""Bounded DEVELOPMENT-only Q6 GGUF → typed agent adapter.

The Q6_K selector is an untrusted adviser. This implementation neither grants
tool authority nor asserts final-research model identity. A separately attested
server process and independent qualification are required before final use.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from pydantic import BaseModel

from llm.prompt_catalog import PromptCatalog
from schemas.common import AgentRole
from schemas.experiment_results import ProviderCallUsage, TokenUsageStatus
from schemas.experiments import ModelConfiguration, ProviderDescriptor


class LocalGgufProviderError(RuntimeError):
    """One model call failed or produced an invalid structured response."""


class LocalGgufDevelopmentProvider:
    """A single-request, loopback-only llama.cpp JSON adapter with raw evidence.

    The descriptor is deliberately not final-capable: knowing the on-disk model
    hash does not prove which weights an independently running server loaded.
    """

    def __init__(
        self,
        *,
        model_path: Path,
        expected_model_sha256: str,
        configuration: ModelConfiguration,
        prompts: PromptCatalog,
        evidence_dir: Path,
        port: int = 18080,
        timeout_seconds: int = 600,
        top_p: float = 0.8,
        top_k: int = 20,
    ) -> None:
        if configuration.provider != "llama_cpp":
            raise ValueError("only the llama_cpp provider identity is supported")
        if not (1024 <= port <= 65535) or not (1 <= timeout_seconds <= 600):
            raise ValueError("invalid local port or bounded timeout")
        if len(expected_model_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in expected_model_sha256
        ):
            raise ValueError("invalid pinned model SHA-256")
        if not (0 < top_p <= 1) or not (1 <= top_k <= 100):
            raise ValueError("invalid frozen sampler limits")
        model_input = Path(model_path)
        if any(component.is_symlink() for component in (model_input, *model_input.parents)):
            raise ValueError("model path must not contain symlinks")
        p = model_input.resolve(strict=True)
        if not p.is_file():
            raise ValueError("model must be a regular file")
        digest = sha256()
        with p.open("rb") as stream:
            for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_model_sha256:
            raise ValueError("model hash does not match the frozen artifact")
        evidence_input = Path(evidence_dir)
        if any(component.is_symlink() for component in (evidence_input, *evidence_input.parents)):
            raise ValueError("evidence directory path must not contain symlinks")
        evidence = evidence_input.resolve(strict=True)
        if not evidence.is_dir():
            raise ValueError("pre-existing regular evidence directory is required")
        self.model_path = p
        self.model_sha256 = expected_model_sha256
        self.configuration = configuration
        self.prompts = prompts
        self.evidence_dir = evidence
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.top_p = top_p
        self.top_k = top_k
        self._file_stat = (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
        self._sequence = 0
        self._usage = ProviderCallUsage()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider=self.configuration.provider,
            model_name=self.configuration.model_name,
            temperature=self.configuration.temperature,
            max_output_tokens=self.configuration.max_output_tokens,
            seed=self.configuration.seed,
            identity_verified=False,
            final_capable=False,
            research_recording=False,
        )

    def take_last_usage(self) -> ProviderCallUsage:
        usage, self._usage = self._usage, ProviderCallUsage()
        return usage

    def _write_once(self, path: Path, payload: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

    def generate_structured(
        self, *, role: AgentRole, input_data: Mapping[str, Any], response_model: type[BaseModel]
    ) -> Mapping[str, Any]:
        self._usage = ProviderCallUsage()
        st = self.model_path.stat()
        if (st.st_ino, st.st_size, st.st_mtime_ns) != self._file_stat:
            raise LocalGgufProviderError("pinned model changed since initialization")
        asset = self.prompts.get(role)
        if not issubclass(response_model, BaseModel):
            raise LocalGgufProviderError("a typed Pydantic output is required")
        # Refuse values that are not serializable under the expected model-visible schema.
        user_payload = json.dumps(
            dict(input_data), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        response_schema = response_model.model_json_schema()
        body = {
            "model": self.configuration.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": asset.system_prompt
                    + "\nReturn a single valid JSON object; schema:\n"
                    + json.dumps(response_schema, sort_keys=True, separators=(",", ":")),
                },
                {"role": "user", "content": user_payload},
            ],
            "temperature": self.configuration.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "max_tokens": self.configuration.max_output_tokens,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        if self.configuration.seed is not None:
            body["seed"] = self.configuration.seed
        raw_request = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        self._sequence += 1
        prefix = f"call-{self._sequence:06d}"
        self._write_once(self.evidence_dir / f"{prefix}-request.json", raw_request)
        raw_response = b""
        status = "FAILED"
        error_type = None
        try:
            req = Request(
                url=f"http://127.0.0.1:{self.port}/v1/chat/completions",
                data=raw_request,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=self.timeout_seconds) as res:
                if res.status != 200:
                    raise LocalGgufProviderError("non-200 response from pinned local endpoint")
                raw_response = res.read(2 * 1024 * 1024 + 1)
            if len(raw_response) > 2 * 1024 * 1024:
                raise LocalGgufProviderError("model response exceeds bounded capture size")
            reply = json.loads(raw_response)
            choices = reply["choices"]
            if len(choices) != 1 or choices[0].get("finish_reason") != "stop":
                raise LocalGgufProviderError("model did not stop normally")
            message = choices[0]["message"]
            if message.get("tool_calls") or not isinstance(message.get("content"), str):
                raise LocalGgufProviderError("tool call or non-text completion rejected")
            parsed = response_model.model_validate(json.loads(message["content"]))
            token_usage = reply.get("usage")
            if isinstance(token_usage, dict):
                inp, out = token_usage.get("prompt_tokens"), token_usage.get("completion_tokens")
                if type(inp) is int and type(out) is int and inp >= 0 and out >= 0:
                    self._usage = ProviderCallUsage(
                        input_tokens=inp,
                        output_tokens=out,
                        token_usage_status=TokenUsageStatus.REPORTED,
                    )
            status = "COMPLETED"
            return parsed.model_dump(mode="json")
        except Exception as exc:
            error_type = type(exc).__name__
            raise LocalGgufProviderError("local model call failed validation or transport") from exc
        finally:
            # Always record one attempted dispatch, including malformed or failed calls.
            self._write_once(self.evidence_dir / f"{prefix}-response.raw", raw_response)
            receipt = {
                "status": status,
                "error_type": error_type,
                "role": role.value,
                "model_sha256": self.model_sha256,
                "prompt_id": asset.prompt_id,
                "prompt_version": asset.version,
                "request_sha256": sha256(raw_request).hexdigest(),
                "response_sha256": sha256(raw_response).hexdigest(),
                "usage": self._usage.model_dump(mode="json"),
                "final_capable": False,
            }
            self._write_once(
                self.evidence_dir / f"{prefix}-receipt.json",
                (json.dumps(receipt, sort_keys=True) + "\n").encode(),
            )
