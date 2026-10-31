"""Read-only loader for explicit versioned prompt assets."""

from __future__ import annotations

from pathlib import Path

from schemas.common import AgentRole
from schemas.prompts import PromptAsset


class PromptCatalogError(RuntimeError):
    pass


class PromptCatalog:
    """Load a fixed prompt directory without inventing defaults or fallbacks."""

    def __init__(self, assets: tuple[PromptAsset, ...]) -> None:
        if not assets:
            raise PromptCatalogError("prompt catalog cannot be empty")
        by_role = {asset.role: asset for asset in assets}
        if len(by_role) != len(assets):
            raise PromptCatalogError("prompt catalog may contain only one asset per role")
        ids = {asset.prompt_id for asset in assets}
        if len(ids) != len(assets):
            raise PromptCatalogError("prompt IDs must be unique")
        self._by_role = by_role

    @classmethod
    def load(cls, directory: Path) -> "PromptCatalog":
        try:
            paths = tuple(sorted(directory.glob("*.json")))
        except OSError as exc:
            raise PromptCatalogError(f"could not inspect prompt directory: {directory}") from exc
        if not paths:
            raise PromptCatalogError("prompt directory contains no JSON assets")
        assets: list[PromptAsset] = []
        for path in paths:
            try:
                assets.append(PromptAsset.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                raise PromptCatalogError(f"invalid prompt asset: {path}") from exc
        return cls(tuple(assets))

    def get(self, role: AgentRole) -> PromptAsset:
        try:
            return self._by_role[role]
        except KeyError as exc:
            raise PromptCatalogError(f"no frozen prompt is registered for role: {role.value}") from exc

    def assets(self) -> tuple[PromptAsset, ...]:
        return tuple(self._by_role[role] for role in sorted(self._by_role, key=lambda item: item.value))
