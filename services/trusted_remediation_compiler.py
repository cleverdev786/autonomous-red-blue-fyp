"""R3 DEVELOPMENT-ONLY trusted, narrow source repair preparation.

Sandbox implementation. No provider, Git, Docker, patch application, or DB writes.
Untrusted Blue output supplies classification/localization only, never replacement text.
"""
from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, SourceReadResult
from schemas.common import ClassificationLabel, WorkflowState
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import (
    PatchGenerationResult, PatchProposal, ProposedFileChange, PreparedPatch,
)
from services.audit_service import AuditService
from services.patch_service import PatchService, PatchServiceError
from services.source_reader import SourceReader, SourceReaderError
from services.target_registry import TargetRegistry

TARGET = "vulnerable-store"
SOURCE = "dummy_apps/vulnerable_store/app/scenario_routes.py"
EXPECTED_SOURCE_SHA256 = "f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d"
COMPILER_VERSION = "r3-trusted-builder-sandbox-v1"


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    category: ClassificationLabel
    function: str
    route_path: str
    http_method: str
    strategy: str
    inbound_symbol: str
    vulnerable_first: int
    vulnerable_last: int


RULES: tuple[Rule, ...] = (
    Rule("r3-sqli-login-v1", ClassificationLabel.SQL_INJECTION,
         "vulnerable_login", "/sql-injection/login", "post",
         "sqlalchemy_named_bind", "payload.username", 46, 53),
    Rule("r3-xss-search-v1", ClassificationLabel.XSS,
         "vulnerable_search", "/xss/search", "get",
         "html_text_escape", "q", 81, 87),
    Rule("r3-public-read-v1", ClassificationLabel.PATH_TRAVERSAL,
         "vulnerable_file_read", "/path-traversal/read", "get",
         "canonical_public_root", "path", 94, 105),
)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode()


class TrustedCompilerProvenance(BaseModel):
    """Deterministic builder provenance, NEVER model-decision provenance.

    Future storage integration must keep this distinct from
    RemediationAttemptResult.PREPARED, which requires real model response hashes.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r3-deterministic-v1"] = "r3-deterministic-v1"
    run_id: str
    target_id: str
    attempt_number: int = Field(ge=1)
    origin: Literal["trusted_deterministic_builder"] = "trusted_deterministic_builder"
    model_decision_used: Literal[False] = False
    model_input_sha256: None = None
    model_response_sha256: None = None
    status: Literal["prepared", "rejected"]
    reason_code: str
    rule_id: str | None
    strategy: str | None
    source_file: str | None
    source_sha256: str | None
    function_ast_sha256: str | None
    blue_analysis_sha256: str
    compiler_version: str
    compiler_sha256: str
    proposal_sha256: str | None
    prepared_diff_sha256: str | None


@dataclass(frozen=True, slots=True)
class TrustedCompilerOutcome:
    provenance: TrustedCompilerProvenance
    generation: PatchGenerationResult | None

    def __post_init__(self):
        if (self.provenance.status == "prepared") != (self.generation is not None):
            raise ValueError("prepared status and actual PatchGenerationResult must agree")
        if self.provenance.status == "prepared":
            assert self.generation is not None
            if self.provenance.prepared_diff_sha256 != self.generation.prepared_patch.diff_sha256:
                raise ValueError("incorrect prepared patch provenance")


class CompilerReject(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


_SQL_OLD = (
    '        query = (\n'
    '            "SELECT username, display_name FROM users "\n'
    '            f"WHERE username = \'{payload.username}\' "\n'
    '            f"AND password_hash = \'{password_hash}\' "\n'
    '            "LIMIT 1"\n'
    '        )'
)
_SQL_NEW = (
    '        query = (\n'
    '            "SELECT username, display_name FROM users "\n'
    '            "WHERE username = :username "\n'
    '            "AND password_hash = :password_hash "\n'
    '            "LIMIT 1"\n'
    '        )'
)
_SQL_EXEC_OLD = "session.execute(text(query))"
_SQL_EXEC_NEW = 'session.execute(text(query), {"username": payload.username, "password_hash": password_hash})'
_XSS_IMPORT_OLD = "from __future__ import annotations\n\nfrom pathlib import Path\n"
_XSS_IMPORT_NEW = "from __future__ import annotations\n\nfrom html import escape\nfrom pathlib import Path\n"
_XSS_SINK_OLD = 'f"<p id=\\"result\\">Search term: {q}</p>"'
_XSS_SINK_NEW = 'f"<p id=\\"result\\">Search term: {escape(q, quote=False)}</p>"'
_PATH_OLD = "candidate.relative_to(scenario_root)"
_PATH_NEW = "candidate.relative_to(intended_public_root)"


def _changes(rule: Rule, source: str):
    if rule.strategy == "sqlalchemy_named_bind":
        edits = ((_SQL_OLD, _SQL_NEW), (_SQL_EXEC_OLD, _SQL_EXEC_NEW))
    elif rule.strategy == "html_text_escape":
        edits = ((_XSS_IMPORT_OLD, _XSS_IMPORT_NEW), (_XSS_SINK_OLD, _XSS_SINK_NEW))
    elif rule.strategy == "canonical_public_root":
        edits = ((_PATH_OLD, _PATH_NEW),)
    else:
        raise CompilerReject("unsupported_strategy")
    for old, new in edits:
        if source.count(old) != 1 or old == new:
            raise CompilerReject("ambiguous_or_missing_exact_anchor")
    return tuple(
        ProposedFileChange(file_path=SOURCE, original_content=old,
                           replacement_content=new,
                           rationale=f"Fixed trusted template {rule.rule_id}: {rule.strategy}.")
        for old, new in edits
    )


def _function_ast(source: str, rule: Rule) -> str:
    try:
        module=ast.parse(source)
    except SyntaxError as exc:
        raise CompilerReject("invalid_python_ast") from exc
    outer=[n for n in module.body if isinstance(n, ast.FunctionDef) and n.name=="build_scenario_router"]
    if len(outer)!=1:
        raise CompilerReject("outer_router_shape_changed")
    nested=[n for n in outer[0].body if isinstance(n, ast.FunctionDef) and n.name==rule.function]
    if len(nested)!=1:
        raise CompilerReject("registered_route_missing_or_duplicated")
    function=nested[0]
    match=False
    for decorator in function.decorator_list:
        if (isinstance(decorator, ast.Call)
            and isinstance(decorator.func,ast.Attribute)
            and isinstance(decorator.func.value,ast.Name)
            and decorator.func.value.id=="local_router"
            and decorator.func.attr==rule.http_method
            and len(decorator.args)>=1
            and isinstance(decorator.args[0],ast.Constant)
            and decorator.args[0].value==rule.route_path):
            match=True
    if not match:
        raise CompilerReject("route_decorator_not_recognized")
    if rule.inbound_symbol.split(".")[0] not in [a.arg for a in function.args.args]:
        raise CompilerReject("untrusted_parameter_not_in_function")
    return sha(ast.dump(function,include_attributes=False).encode())


def _trusted_candidate_function(analysis: BlueTeamAnalysisResult) -> Rule:
    if analysis.target_id!=TARGET:
        raise CompilerReject("unregistered_target")
    if analysis.final_state!=WorkflowState.CODE_ANALYSIS:
        raise CompilerReject("non_actionable_blue_state")
    if not analysis.triage.is_suspicious or analysis.triage.run_id!=analysis.run_id:
        raise CompilerReject("blue_triage_invalid")
    finding=analysis.code_finding
    if finding is None or finding.run_id!=analysis.run_id:
        raise CompilerReject("blue_finding_missing_or_wrong_run")
    if finding.file_path!=SOURCE:
        raise CompilerReject("source_path_not_supported")
    options=[r for r in RULES if r.category==analysis.triage.classification
             and r.function==finding.function_or_route]
    if len(options)!=1:
        raise CompilerReject("unregistered_blue_class_or_function")
    rule=options[0]
    if not any(line.start_line<=rule.vulnerable_last and line.end_line>=rule.vulnerable_first
               for line in finding.supporting_lines):
        raise CompilerReject("finding_lines_do_not_cover_sink")
    return rule


class TrustedRemediationCompiler:
    """Compile fixed approved source templates with no LLM inference."""

    def __init__(self, *, project_root: Path, registry: TargetRegistry,
                 policy_engine: PolicyEngine, audit_service: AuditService) -> None:
        self.project_root=project_root.resolve(strict=False)
        self.policy_engine=policy_engine
        self.audit_service=audit_service
        self.reader=SourceReader(registry=registry,policy_engine=policy_engine,
                                 audit_service=audit_service,project_root=project_root)
        self.patcher=PatchService(registry=registry,policy_engine=policy_engine,
                                  audit_service=audit_service,project_root=project_root)

    def prepare(self, *, analysis: BlueTeamAnalysisResult,
                attempt_number: int, limits: RunLimitTracker) -> TrustedCompilerOutcome:
        rule=None
        source_sha=None
        ast_sha=None
        proposal_sha=None
        diff_sha=None
        generation=None
        reason="prepared"
        if attempt_number<1:
            raise ValueError("attempt_number must be >=1")
        compiler_sha=sha(Path(__file__).read_bytes())
        blue_sha=sha(canon(analysis.model_dump(mode="json")))
        try:
            rule=_trusted_candidate_function(analysis)
            path=self.project_root/SOURCE
            if path.is_symlink() or not path.is_file():
                raise CompilerReject("source_not_regular")
            actual_source=path.read_bytes()
            source_sha=sha(actual_source)
            if source_sha!=EXPECTED_SOURCE_SHA256:
                raise CompilerReject("source_hash_drift")
            text=actual_source.decode("utf-8",errors="strict")
            ast_sha=_function_ast(text,rule)
            decision=self.policy_engine.validate_strategy_selection(
                strategy_id=rule.strategy,
                registered_strategy_ids=tuple(r.strategy for r in RULES),
                allowed_strategy_ids=tuple(r.strategy for r in RULES))
            if not decision.allowed:
                raise CompilerReject("strategy_policy_denied")
            decision=self.policy_engine.validate_patch_attempt_budget(limits)
            if not decision.allowed:
                raise CompilerReject("patch_attempt_budget_denied")

            # Source is read through the existing policy-controlled source reader.
            header=self.reader.read_file(run_id=analysis.run_id,
                target_id=TARGET,relative_path=SOURCE,start_line=1,max_lines=30)
            start=max(1,rule.vulnerable_first-12)
            body=self.reader.read_file(run_id=analysis.run_id,
                target_id=TARGET,relative_path=SOURCE,start_line=start,max_lines=70)
            context=SourceReadResult(run_id=analysis.run_id,target_id=TARGET,
                snippets=(header,body),route_names=(rule.function,))
            edits=_changes(rule,text)
            # All edits must be grounded in exact, bounded source-reader excerpts.
            for edit in edits:
                if not any(edit.original_content in s.content for s in context.snippets):
                    raise CompilerReject("source_snippet_does_not_ground_edit")
            proposal=PatchProposal(run_id=analysis.run_id,target_id=TARGET,
                attempt_number=attempt_number,changes=edits,
                security_rationale=f"Trusted {rule.rule_id}; deterministic pattern match.",
                expected_effect=f"Registered {rule.strategy} remediation.",
                regression_risks=("Require registered security replay and regressions.",))
            proposal_sha=sha(canon(proposal.model_dump(mode="json")))
            limits.consume_patch_attempts()
            prepared=self.patcher.prepare_patch(
                proposal=proposal,code_finding=analysis.code_finding,source_context=context)
            diff_sha=prepared.diff_sha256
            # Validate the replacement stays in a syntactically valid Python file,
            # without writing any content or executing the replacement.
            ast.parse(prepared.files[0].replacement_content)
            if prepared.files_changed!=1 or prepared.files[0].file_path!=SOURCE:
                raise CompilerReject("prepared_patch_outside_one_file")
            generation=PatchGenerationResult(run_id=analysis.run_id,target_id=TARGET,
                attempt_number=attempt_number,proposal=proposal,
                prepared_patch=prepared,final_state=WorkflowState.PATCH_VALIDATING)
        except (CompilerReject, PatchServiceError, SourceReaderError, ValueError, UnicodeError, SyntaxError) as exc:
            reason=exc.reason_code if isinstance(exc,CompilerReject) else "trusted_preparation_"+type(exc).__name__
        provenance=TrustedCompilerProvenance(
            run_id=analysis.run_id,target_id=analysis.target_id,
            attempt_number=attempt_number,
            status="prepared" if generation is not None else "rejected",
            reason_code=reason,rule_id=rule.rule_id if rule else None,
            strategy=rule.strategy if rule else None,
            source_file=SOURCE if rule else None,
            source_sha256=source_sha,function_ast_sha256=ast_sha,
            blue_analysis_sha256=blue_sha,compiler_version=COMPILER_VERSION,
            compiler_sha256=compiler_sha,
            proposal_sha256=proposal_sha if generation is not None else None,
            prepared_diff_sha256=diff_sha if generation is not None else None,
        )
        self.audit_service.record(run_id=analysis.run_id,component="trusted_r3_compiler",
            actor_type="deterministic_service",operation="trusted_template_prepare",
            target=rule.rule_id if rule else TARGET,
            policy_decision=(AuditPolicyDecision.ALLOWED if generation else AuditPolicyDecision.BLOCKED),
            execution_status=(AuditExecutionStatus.SUCCEEDED if generation else AuditExecutionStatus.BLOCKED),
            evidence_reference=sha(canon(provenance.model_dump(mode="json"))),
            error_code=None if generation else "trusted-compiler-rejected")
        return TrustedCompilerOutcome(provenance=provenance,generation=generation)
