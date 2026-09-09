"""Deterministic reward-guided selection over trusted registered strategies."""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from collections.abc import Iterable

from orchestrator.policy_engine import PolicyEngine
from schemas.experience import (
    ExperienceSnapshot,
    SelectionDecision,
    StrategyHistoryObservation,
)
from schemas.experiments import ExperienceMode
from services.experience_store import ExperienceStore


class SelectionPolicyError(RuntimeError):
    """Raised when trusted strategy selection cannot be completed safely."""


class SelectionPolicy:
    """Rank only caller-registered strategies after deterministic policy filtering."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        registered_strategy_ids: Iterable[str],
    ) -> None:
        registered = tuple(sorted(set(registered_strategy_ids)))
        if not registered:
            raise ValueError("at least one trusted strategy must be registered")
        self.policy_engine = policy_engine
        self.registered_strategy_ids = registered

    def select(
        self,
        *,
        run_id: str,
        scenario_id: str,
        experience_mode: ExperienceMode,
        candidate_strategy_ids: tuple[str, ...],
        policy_allowed_strategy_ids: tuple[str, ...],
        configured_strategy_id: str,
        experience_store: ExperienceStore | None = None,
        frozen_snapshot: ExperienceSnapshot | None = None,
    ) -> SelectionDecision:
        """Select one trusted strategy; disabled mode performs no experience lookup."""
        candidates = tuple(dict.fromkeys(candidate_strategy_ids))
        if not candidates:
            raise SelectionPolicyError("candidate_strategy_ids must not be empty")

        unknown = tuple(
            item for item in candidates if item not in self.registered_strategy_ids
        )
        if unknown:
            raise SelectionPolicyError(
                f"unregistered strategy candidate(s): {', '.join(sorted(unknown))}"
            )
        if configured_strategy_id not in self.registered_strategy_ids:
            raise SelectionPolicyError("configured strategy is not registered")

        eligible = tuple(
            item
            for item in candidates
            if self.policy_engine.validate_strategy_selection(
                strategy_id=item,
                registered_strategy_ids=self.registered_strategy_ids,
                allowed_strategy_ids=policy_allowed_strategy_ids,
            ).allowed
        )
        if not eligible:
            raise SelectionPolicyError("policy rejected every candidate strategy")

        if experience_mode == ExperienceMode.DISABLED:
            if configured_strategy_id not in eligible:
                raise SelectionPolicyError("configured strategy is not policy-approved")
            return SelectionDecision(
                run_id=run_id,
                experience_mode=experience_mode,
                scenario_id=scenario_id,
                candidate_strategy_ids=candidates,
                eligible_strategy_ids=eligible,
                selected_strategy_id=configured_strategy_id,
                history_limit_per_strategy=0,
                reason="experience disabled; selected the configured trusted strategy",
            )

        if experience_mode == ExperienceMode.FROZEN_IDENTICAL:
            if frozen_snapshot is None:
                raise SelectionPolicyError("frozen experience mode requires a supplied snapshot")
            if frozen_snapshot.scenario_id != scenario_id:
                raise SelectionPolicyError("frozen experience snapshot scenario does not match")
            snapshot = frozen_snapshot
        elif experience_mode == ExperienceMode.ENABLED_EXPLORATORY:
            if experience_store is None:
                raise SelectionPolicyError("exploratory experience mode requires ExperienceStore")
            snapshot = experience_store.load_snapshot(
                scenario_id=scenario_id,
                registered_strategy_ids=self.registered_strategy_ids,
                exclude_run_id=run_id,
            )
        else:  # pragma: no cover - enum exhaustiveness guard
            raise SelectionPolicyError(f"unsupported experience mode: {experience_mode!r}")

        observations = tuple(
            self._observation(strategy_id, snapshot)
            for strategy_id in eligible
        )
        scored_observations = tuple(
            item for item in observations if item.scored_history_count > 0
        )
        if not scored_observations:
            if configured_strategy_id in eligible:
                selected = configured_strategy_id
                reason = "no comparable scored experience; selected the configured trusted strategy"
            else:
                selected = sorted(eligible)[0]
                reason = (
                    "no comparable scored experience and the configured strategy was policy-blocked; "
                    "selected the first policy-approved registered strategy by deterministic lexical order"
                )
        else:
            selected = min(
                scored_observations,
                key=lambda item: self._rank_key(item),
            ).strategy_id
            reason = (
                "selected highest deterministic historical rank among registered, "
                "policy-approved strategies; missing scores were excluded from reward averages"
            )

        return SelectionDecision(
            run_id=run_id,
            experience_mode=experience_mode,
            scenario_id=scenario_id,
            candidate_strategy_ids=candidates,
            eligible_strategy_ids=eligible,
            selected_strategy_id=selected,
            history_limit_per_strategy=snapshot.history_limit_per_strategy,
            snapshot_sha256=self._snapshot_sha256(snapshot),
            observations=observations,
            reason=reason,
        )

    @staticmethod
    def _observation(
        strategy_id: str,
        snapshot: ExperienceSnapshot,
    ) -> StrategyHistoryObservation:
        history = tuple(
            item for item in snapshot.summaries if item.strategy_id == strategy_id
        )
        scored = tuple(item.blue_score for item in history if item.blue_score is not None)
        total = len(history)
        denominator = Decimal(total) if total else Decimal(1)
        mean_score = (
            sum(scored, Decimal(0)) / Decimal(len(scored))
            if scored
            else None
        )
        return StrategyHistoryObservation(
            strategy_id=strategy_id,
            total_history_count=total,
            scored_history_count=len(scored),
            mean_blue_score=mean_score,
            patch_acceptance_rate=(
                Decimal(sum(1 for item in history if item.patch_accepted)) / denominator
                if total
                else Decimal(0)
            ),
            regression_rate=(
                Decimal(sum(1 for item in history if item.regression_detected)) / denominator
                if total
                else Decimal(0)
            ),
            policy_block_count=sum(item.policy_block_count for item in history),
            duplicate_patch_count=sum(item.duplicate_patch_count for item in history),
            mean_attempt_count=(
                Decimal(sum(item.attempt_count for item in history)) / denominator
                if total
                else Decimal(0)
            ),
        )

    @staticmethod
    def _rank_key(item: StrategyHistoryObservation) -> tuple:
        assert item.mean_blue_score is not None
        return (
            -item.mean_blue_score,
            -item.patch_acceptance_rate,
            item.regression_rate,
            item.policy_block_count,
            item.duplicate_patch_count,
            item.mean_attempt_count,
            item.strategy_id,
        )

    @staticmethod
    def _snapshot_sha256(snapshot: ExperienceSnapshot) -> str:
        payload = json.dumps(
            snapshot.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
