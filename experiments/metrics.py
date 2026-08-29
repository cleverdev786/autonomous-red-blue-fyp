"""Deterministic research metrics recomputed from stored raw evidence."""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal
import statistics

from sqlalchemy import func, select

from schemas.common import ClassificationLabel, RunType
from storage.models import (
    AgentCallRow,
    ClassificationTruthRow,
    CodeFindingRow,
    DatasetItemRow,
    EventClassificationRow,
    ExperimentConfigurationRow,
    ExperimentRunRow,
    FunctionalCheckRow,
    PatchAttemptRow,
    PolicyEventReferenceRow,
    RunClassificationRow,
    RunProvenanceRow,
    ScenarioTruthRow,
    SecurityTestExecutionRow,
    VerificationStageRow,
)
from storage.repositories import ResearchReadRepository


LABELS = tuple(label.value for label in ClassificationLabel)
ATTACK_LABELS = {ClassificationLabel.SQL_INJECTION.value, ClassificationLabel.XSS.value, ClassificationLabel.PATH_TRAVERSAL.value}


def _rate(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def _summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"count": 0, "mean": None, "median": None, "min": None, "max": None, "stdev": None}
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def _usage(calls: list[AgentCallRow]) -> dict:
    tokens_complete = all(call.input_tokens is not None and call.output_tokens is not None for call in calls)
    costs_complete = all(call.estimated_cost is not None for call in calls)
    return {
        "model_calls": len(calls),
        "input_tokens": sum(call.input_tokens or 0 for call in calls) if tokens_complete else None,
        "output_tokens": sum(call.output_tokens or 0 for call in calls) if tokens_complete else None,
        "estimated_cost": str(sum((call.estimated_cost or Decimal("0")) for call in calls)) if costs_complete else None,
        "token_usage_complete": tokens_complete,
        "cost_usage_complete": costs_complete,
    }


def _scoped_runs(session, *, rq: str, final_only: bool, config_id: str | None = None):
    statement = (
        select(ExperimentRunRow, ExperimentConfigurationRow)
        .join(ExperimentConfigurationRow, ExperimentRunRow.config_id == ExperimentConfigurationRow.config_id)
        .where(ExperimentConfigurationRow.research_question == rq)
    )
    if final_only:
        statement = statement.where(ExperimentConfigurationRow.run_type == RunType.FINAL_EVALUATION.value)
    if config_id is not None:
        statement = statement.where(ExperimentRunRow.config_id == config_id)
    return session.execute(statement).all()


def compute_rq1_metrics(repository: ResearchReadRepository, *, final_only: bool = True, config_id: str | None = None) -> dict:
    with repository.session() as session:
        pairs = _scoped_runs(session, rq="rq1", final_only=final_only, config_id=config_id)
        grouped: dict[str, list[ExperimentRunRow]] = defaultdict(list)
        for run, config in pairs:
            grouped[config.blue_team_mode].append(run)

        output = {}
        for condition, runs in grouped.items():
            run_ids = [run.run_id for run in runs]
            attempts = list(session.scalars(select(PatchAttemptRow).where(PatchAttemptRow.run_id.in_(run_ids)))) if run_ids else []
            accepted = [a for a in attempts if a.final_state == "accepted"]
            repaired = {a.run_id for a in accepted}
            stages = list(session.scalars(
                select(VerificationStageRow).join(PatchAttemptRow, VerificationStageRow.patch_attempt_id == PatchAttemptRow.id).where(PatchAttemptRow.run_id.in_(run_ids))
            )) if run_ids else []
            regression = [s for s in stages if s.stage_id == "regression"]
            replay = [s for s in stages if s.stage_id == "original_replay"]

            run_class = {row.run_id: row for row in session.scalars(select(RunClassificationRow).where(RunClassificationRow.run_id.in_(run_ids)))} if run_ids else {}
            findings = {row.run_id: row for row in session.scalars(select(CodeFindingRow).where(CodeFindingRow.run_id.in_(run_ids)))} if run_ids else {}
            truths = {}
            for run in runs:
                prov = session.get(RunProvenanceRow, run.run_id)
                if run.scenario_id and prov and prov.scenario_version:
                    truth = session.scalar(select(ScenarioTruthRow).where(ScenarioTruthRow.scenario_id == run.scenario_id, ScenarioTruthRow.scenario_version == prov.scenario_version))
                    if truth:
                        truths[run.run_id] = truth

            evaluated_class = [rid for rid in run_ids if rid in run_class and rid in truths]
            evaluated_find = [rid for rid in run_ids if rid in findings and rid in truths]
            classification_correct = sum(run_class[rid].predicted_label == truths[rid].vulnerability_class for rid in evaluated_class)
            file_correct = sum(findings[rid].file_path == truths[rid].source_file for rid in evaluated_find)
            function_correct = sum(findings[rid].function_or_route == truths[rid].function_or_route for rid in evaluated_find)

            first_patch_times = []
            accepted_times = []
            attempts_per_run = []
            for run in runs:
                own = [a for a in attempts if a.run_id == run.run_id]
                attempts_per_run.append(float(len(own)))
                prepared = [a.patch_prepared_at for a in own if a.patch_prepared_at is not None]
                if prepared:
                    first_patch_times.append((min(prepared) - run.started_at).total_seconds() * 1000)
                decisions = [a.verification_decision_at for a in own if a.final_state == "accepted" and a.verification_decision_at is not None]
                if decisions:
                    accepted_times.append((min(decisions) - run.started_at).total_seconds() * 1000)
            runtimes = [((run.completed_at - run.started_at).total_seconds() * 1000) for run in runs if run.completed_at is not None]
            calls = list(session.scalars(select(AgentCallRow).where(AgentCallRow.run_id.in_(run_ids)))) if run_ids else []

            output[condition] = {
                "sample_size_runs": len(runs),
                "patch_attempts": len(attempts),
                "accepted_patch_attempts": len(accepted),
                "patch_acceptance_rate": _rate(len(accepted), len(attempts)),
                "eventual_repair_rate": _rate(len(repaired), len(runs)),
                "original_replay_pass_rate": _rate(sum(s.passed for s in replay), len(replay)),
                "regression_rate": _rate(sum(not s.passed for s in regression), len(regression)),
                "classification_accuracy": _rate(classification_correct, len(evaluated_class)),
                "source_file_localization_accuracy": _rate(file_correct, len(evaluated_find)),
                "function_localization_accuracy": _rate(function_correct, len(evaluated_find)),
                "patch_attempts_per_run": _summary(attempts_per_run),
                "time_to_first_patch_ms": _summary(first_patch_times),
                "time_to_accepted_patch_ms": _summary(accepted_times),
                "total_run_time_ms": _summary(runtimes),
                "model_usage": _usage(calls),
            }
        return {"final_only": final_only, "conditions": output}


def compute_rq2_metrics(repository: ResearchReadRepository, *, final_only: bool = True, config_id: str | None = None) -> dict:
    with repository.session() as session:
        pairs = _scoped_runs(session, rq="rq2", final_only=final_only, config_id=config_id)
        grouped: dict[str, list[ExperimentRunRow]] = defaultdict(list)
        for run, config in pairs:
            grouped[config.classification_mode].append(run)
        output = {}
        for mode, runs in grouped.items():
            run_ids = [run.run_id for run in runs]
            predictions = list(session.scalars(select(EventClassificationRow).where(EventClassificationRow.run_id.in_(run_ids)))) if run_ids else []
            truth_by_item = {row.dataset_item_id: row.ground_truth_label for row in session.scalars(select(ClassificationTruthRow).where(ClassificationTruthRow.dataset_item_id.in_([p.dataset_item_id for p in predictions])))} if predictions else {}
            pairs_label = [(p.predicted_label, truth_by_item[p.dataset_item_id]) for p in predictions if p.dataset_item_id in truth_by_item]
            matrix = {actual: {predicted: 0 for predicted in LABELS} for actual in LABELS}
            for predicted, actual in pairs_label:
                matrix[actual][predicted] += 1
            per_class = {}
            for label in LABELS:
                tp = matrix[label][label]
                fp = sum(matrix[actual][label] for actual in LABELS if actual != label)
                fn = sum(matrix[label][pred] for pred in LABELS if pred != label)
                precision = _rate(tp, tp + fp)
                recall = _rate(tp, tp + fn)
                f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
                per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": sum(matrix[label].values())}
            correct = sum(predicted == actual for predicted, actual in pairs_label)
            benign_total = sum(matrix[ClassificationLabel.BENIGN.value].values())
            benign_fp = sum(matrix[ClassificationLabel.BENIGN.value][label] for label in ATTACK_LABELS)
            attack_pairs = [(p, a) for p, a in pairs_label if a in ATTACK_LABELS]
            attack_detected = sum(p in ATTACK_LABELS for p, _ in attack_pairs)
            calls = list(session.scalars(select(AgentCallRow).where(AgentCallRow.run_id.in_(run_ids)))) if run_ids else []
            output[mode] = {
                "sample_size_events": len(pairs_label),
                "confusion_matrix": matrix,
                "accuracy": _rate(correct, len(pairs_label)),
                "per_class": per_class,
                "macro_f1": statistics.mean(item["f1"] for item in per_class.values()),
                "attack_detection_rate": _rate(attack_detected, len(attack_pairs)),
                "benign_false_positive_rate": _rate(benign_fp, benign_total),
                "unknown_rate": _rate(sum(predicted == ClassificationLabel.UNKNOWN.value for predicted, _ in pairs_label), len(pairs_label)),
                "classification_time_ms": _summary([float(p.duration_ms) for p in predictions]),
                "model_usage": _usage(calls),
            }
        return {"final_only": final_only, "conditions": output}


def compute_rq3_metrics(repository: ResearchReadRepository, *, final_only: bool = True, config_id: str | None = None) -> dict:
    with repository.session() as session:
        pairs = _scoped_runs(session, rq="rq3", final_only=final_only, config_id=config_id)
        grouped: dict[str, list[ExperimentRunRow]] = defaultdict(list)
        for run, config in pairs:
            grouped[config.retry_feedback_mode].append(run)
        output = {}
        for mode, runs in grouped.items():
            run_ids = [run.run_id for run in runs]
            attempts = list(session.scalars(select(PatchAttemptRow).where(PatchAttemptRow.run_id.in_(run_ids)))) if run_ids else []
            eligible = []
            second_accepted = 0
            repeated_failures = 0
            accepted_attempt_counts = []
            accepted_times = []
            for run in runs:
                own = sorted([a for a in attempts if a.run_id == run.run_id], key=lambda a: a.attempt_number)
                if len(own) >= 2 and own[0].final_state != "accepted":
                    eligible.append(run.run_id)
                    if own[1].final_state == "accepted": second_accepted += 1
                    else: repeated_failures += 1
                accepted = next((a for a in own if a.final_state == "accepted"), None)
                if accepted:
                    accepted_attempt_counts.append(float(accepted.attempt_number))
                    if accepted.verification_decision_at:
                        accepted_times.append((accepted.verification_decision_at - run.started_at).total_seconds() * 1000)
            stages = list(session.scalars(select(VerificationStageRow).join(PatchAttemptRow, VerificationStageRow.patch_attempt_id == PatchAttemptRow.id).where(PatchAttemptRow.run_id.in_(run_ids), VerificationStageRow.stage_id == "regression"))) if run_ids else []
            retry_calls = list(session.scalars(select(AgentCallRow).where(AgentCallRow.run_id.in_(run_ids), AgentCallRow.patch_attempt_number.is_not(None), AgentCallRow.patch_attempt_number > 1))) if run_ids else []
            output[mode] = {
                "eligible_failed_first_attempt_runs": len(eligible),
                "second_attempt_acceptance_rate": _rate(second_accepted, len(eligible)),
                "repeated_failure_rate": _rate(repeated_failures, len(eligible)),
                "average_attempts_to_accepted_patch": statistics.mean(accepted_attempt_counts) if accepted_attempt_counts else None,
                "regression_rate": _rate(sum(not s.passed for s in stages), len(stages)),
                "time_to_accepted_patch_ms": _summary(accepted_times),
                "additional_model_usage": _usage(retry_calls),
            }
        return {"final_only": final_only, "conditions": output}


def compute_red_metrics(repository: ResearchReadRepository, *, final_only: bool = True) -> dict:
    with repository.session() as session:
        statement = select(SecurityTestExecutionRow, ExperimentRunRow, ExperimentConfigurationRow).join(ExperimentRunRow, SecurityTestExecutionRow.run_id == ExperimentRunRow.run_id).join(ExperimentConfigurationRow, ExperimentRunRow.config_id == ExperimentConfigurationRow.config_id).where(SecurityTestExecutionRow.purpose == "red_attack")
        if final_only:
            statement = statement.where(ExperimentConfigurationRow.run_type == RunType.FINAL_EVALUATION.value)
        rows = session.execute(statement).all()
        executions = [row[0] for row in rows]
        confirmed = [item for item in executions if item.confirmed is True]
        unconfirmed = [item for item in executions if item.confirmed is False]
        reproducible = [item for item in executions if item.exploit_evidence_observed and item.completed and not item.timed_out]
        duplicates = 0
        seen: dict[str, set[str]] = defaultdict(set)
        for item in sorted(executions, key=lambda x: (x.run_id, x.red_attempt_number or 0)):
            if item.test_id in seen[item.run_id]: duplicates += 1
            seen[item.run_id].add(item.test_id)
        run_map = {run.run_id: run for _, run, _ in rows}
        times = []
        for item in confirmed:
            run = run_map[item.run_id]
            if item.completed_at is not None:
                times.append((item.completed_at - run.started_at).total_seconds() * 1000)
        run_ids = list(run_map)
        policy_count = session.scalar(select(func.count()).select_from(PolicyEventReferenceRow).where(PolicyEventReferenceRow.run_id.in_(run_ids))) if run_ids else 0
        return {
            "sample_size_attempts": len(executions),
            "confirmed_attack_success_rate": _rate(len(confirmed), len(executions)),
            "unconfirmed_claim_rate": _rate(len(unconfirmed), len(executions)),
            "reproducible_evidence_rate": _rate(len(reproducible), len(executions)),
            "duplicate_attempt_rate": _rate(duplicates, len(executions)),
            "policy_violation_count": int(policy_count or 0),
            "requests_per_confirmed_vulnerability": (sum(item.request_count for item in confirmed) / len(confirmed)) if confirmed else None,
            "time_to_confirmed_vulnerability_ms": _summary(times),
        }


def compute_normal_application_task_success(repository: ResearchReadRepository, *, final_only: bool = True) -> dict:
    with repository.session() as session:
        statement = select(FunctionalCheckRow, PatchAttemptRow, ExperimentRunRow, ExperimentConfigurationRow).join(PatchAttemptRow, FunctionalCheckRow.patch_attempt_id == PatchAttemptRow.id).join(ExperimentRunRow, PatchAttemptRow.run_id == ExperimentRunRow.run_id).join(ExperimentConfigurationRow, ExperimentRunRow.config_id == ExperimentConfigurationRow.config_id)
        if final_only:
            statement = statement.where(ExperimentConfigurationRow.run_type == RunType.FINAL_EVALUATION.value)
        checks = [row[0] for row in session.execute(statement).all()]
        passed = sum(check.status == "passed" for check in checks)
        return {"passed": passed, "total": len(checks), "normal_application_task_success": _rate(passed, len(checks))}
