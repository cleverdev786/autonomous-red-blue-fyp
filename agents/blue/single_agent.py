"""One general-purpose Blue persona reused across typed RQ1 reasoning stages."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from schemas.common import AgentRole


OutputT = TypeVar("OutputT", bound=BaseModel)
InputBuilder = Callable[..., Mapping[str, Any]]


class SingleGeneralBlueAgent:
    """Create schema adapters that all use the single general Blue role.

    The response schema and input shape may vary by stage, but the provider sees
    one logical persona identity: AgentRole.BLUE_SINGLE_AGENT.
    """

    role = AgentRole.BLUE_SINGLE_AGENT

    def stage(
        self,
        *,
        output_model: type[OutputT],
        input_builder: InputBuilder,
    ) -> "SingleAgentStage[OutputT]":
        return SingleAgentStage(
            output_model=output_model,
            input_builder=input_builder,
        )


class SingleAgentStage(Generic[OutputT]):
    """Typed stage adapter for the single general-purpose Blue persona."""

    role = AgentRole.BLUE_SINGLE_AGENT

    def __init__(
        self,
        *,
        output_model: type[OutputT],
        input_builder: InputBuilder,
    ) -> None:
        self.output_model = output_model
        self._input_builder = input_builder

    def prepare_input(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        return self._input_builder(*args, **kwargs)

    def validate_output(
        self,
        raw_output: Mapping[str, Any] | BaseModel,
    ) -> OutputT:
        return self.output_model.model_validate(raw_output)
