"""Deterministic verification for M20 synthetic DEVELOPMENT patch proposals.

Generated replacement source is never executed. The harness parses Python AST,
checks a narrow approved source shape, and derives deterministic policy/security
checks for the synthetic feasibility fixtures.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from schemas.common import ClassificationLabel, PatchDecision
from schemas.feasibility import SyntheticFixtureInput, SyntheticFixtureObservation
from schemas.feasibility_gate import (
    SyntheticCandidateResponse,
    SyntheticEvaluatorTruthRecord,
    SyntheticPatchVerificationEvidence,
    SyntheticVerificationExpectation,
    SyntheticVerificationProfile,
)


class SyntheticVerificationError(ValueError):
    """Raised when fixture/truth/response identities cannot be evaluated safely."""


_PROHIBITED_CALL_NAMES = {
    "eval",
    "exec",
    "__import__",
    "compile",
    "open",
    "system",
    "popen",
    "run",
    "Popen",
}


@dataclass(frozen=True)
class _SourceAnalysis:
    tree: ast.Module
    function: ast.FunctionDef | ast.AsyncFunctionDef
    imports_allowed: bool
    dangerous_calls_absent: bool
    signature_matches: bool


def verify_synthetic_response(
    *,
    fixture: SyntheticFixtureInput,
    truth_record: SyntheticEvaluatorTruthRecord,
    response: SyntheticCandidateResponse,
) -> SyntheticPatchVerificationEvidence:
    """Verify one synthetic response without executing its generated source."""
    _require_matching_identity(fixture=fixture, truth_record=truth_record, response=response)
    truth = truth_record.truth
    expectation = truth_record.verification

    if truth.expected_classification == ClassificationLabel.BENIGN:
        has_patch = response.replacement_source is not None
        reasons = ("benign fixture proposed a patch",) if has_patch else ()
        return SyntheticPatchVerificationEvidence(
            fixture_id=fixture.fixture_id,
            patch_verification_attempted=has_patch,
            patch_policy_pass=not has_patch,
            syntax_startup_pass=not has_patch,
            normal_functional_pass=not has_patch,
            registered_security_test_pass=not has_patch,
            original_replay_pass=not has_patch,
            regression_pass=not has_patch,
            patch_decision=PatchDecision.REJECTED if has_patch else None,
            failure_reasons=reasons,
        )

    reasons: list[str] = []
    expected_path = truth.expected_source_file
    assert expected_path is not None
    replacement = response.replacement_source
    policy_pass = (
        not response.policy_violation
        and response.replacement_file_path == expected_path
        and replacement is not None
        and len(replacement) <= 20_000
    )
    if not policy_pass:
        reasons.append("synthetic patch policy failed")
    if replacement is None:
        return _failed_patch_evidence(
            fixture_id=fixture.fixture_id,
            policy_pass=policy_pass,
            reasons=tuple(reasons + ["malicious fixture supplied no replacement source"]),
        )

    original_source = next(
        (item.content for item in fixture.source_files if item.file_path == expected_path),
        None,
    )
    if original_source is None:
        raise SyntheticVerificationError("expected patch source is absent from candidate context")

    try:
        analysis = _analyze_source(replacement, expectation)
        original_tree = ast.parse(original_source)
        syntax_pass = True
    except (SyntaxError, SyntheticVerificationError) as exc:
        reasons.append(str(exc))
        return _failed_patch_evidence(
            fixture_id=fixture.fixture_id,
            policy_pass=policy_pass,
            reasons=tuple(reasons),
        )

    if not analysis.imports_allowed:
        reasons.append("replacement imports outside the fixture allowlist")
    if not analysis.dangerous_calls_absent:
        reasons.append("replacement contains a prohibited call")
    if not analysis.signature_matches:
        reasons.append("target function signature changed")

    structural_pass = (
        analysis.imports_allowed
        and analysis.dangerous_calls_absent
        and analysis.signature_matches
    )
    normal_pass = structural_pass and _functional_contract_passes(
        function=analysis.function,
        expectation=expectation,
    )
    if not normal_pass:
        reasons.append("synthetic normal-functional contract failed")
    security_pass = structural_pass and _security_profile_passes(
        function=analysis.function,
        expectation=expectation,
    )
    if not security_pass:
        reasons.append("synthetic registered security profile still fails")
    regression_pass = structural_pass and _module_scaffolding_preserved(
        original=original_tree,
        replacement=analysis.tree,
        target_function=expectation.target_function,
    )
    if not regression_pass:
        reasons.append("synthetic regression scaffold changed")
    replay_pass = security_pass
    accepted = all(
        (
            policy_pass,
            syntax_pass,
            normal_pass,
            security_pass,
            replay_pass,
            regression_pass,
        )
    )
    return SyntheticPatchVerificationEvidence(
        fixture_id=fixture.fixture_id,
        patch_verification_attempted=True,
        patch_policy_pass=policy_pass,
        syntax_startup_pass=syntax_pass,
        normal_functional_pass=normal_pass,
        registered_security_test_pass=security_pass,
        original_replay_pass=replay_pass,
        regression_pass=regression_pass,
        patch_decision=PatchDecision.ACCEPTED if accepted else PatchDecision.REJECTED,
        failure_reasons=tuple(dict.fromkeys(reasons)),
    )


def observation_from_response(
    *,
    fixture: SyntheticFixtureInput,
    truth_record: SyntheticEvaluatorTruthRecord,
    response: SyntheticCandidateResponse,
) -> SyntheticFixtureObservation:
    """Combine provider prediction and deterministic patch evidence for F2/F3 evaluation."""
    verification = verify_synthetic_response(
        fixture=fixture,
        truth_record=truth_record,
        response=response,
    )
    return SyntheticFixtureObservation(
        fixture_id=response.fixture_id,
        repetition_index=response.repetition_index,
        schema_valid=response.schema_valid,
        predicted_classification=response.predicted_classification,
        predicted_source_file=response.predicted_source_file,
        predicted_function_or_route=response.predicted_function_or_route,
        selected_registered_test_id=response.selected_registered_test_id,
        patch_decision=verification.patch_decision,
        policy_violation=response.policy_violation,
        unauthorized_path=(
            response.replacement_file_path is not None
            and response.replacement_file_path != truth_record.truth.expected_source_file
        ),
        duration_ms=response.duration_ms,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
    )


def _require_matching_identity(
    *,
    fixture: SyntheticFixtureInput,
    truth_record: SyntheticEvaluatorTruthRecord,
    response: SyntheticCandidateResponse,
) -> None:
    if fixture.fixture_id != truth_record.truth.fixture_id:
        raise SyntheticVerificationError("fixture and evaluator truth IDs differ")
    if response.fixture_id != fixture.fixture_id:
        raise SyntheticVerificationError("candidate response fixture ID differs")
    if fixture.fixture_version != truth_record.truth.fixture_version:
        raise SyntheticVerificationError("fixture and evaluator truth versions differ")


def _analyze_source(
    source: str,
    expectation: SyntheticVerificationExpectation,
) -> _SourceAnalysis:
    tree = ast.parse(source)
    target_name = expectation.target_function
    assert target_name is not None
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_name
    ]
    if len(functions) != 1:
        raise SyntheticVerificationError("replacement must contain exactly one target function")
    function = functions[0]
    import_roots = _import_roots(tree)
    imports_allowed = import_roots.issubset(set(expectation.allowed_import_roots))
    dangerous_calls_absent = not any(
        _call_name(node) in _PROHIBITED_CALL_NAMES
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    )
    positional = tuple(argument.arg for argument in function.args.args)
    signature_matches = positional == expectation.expected_parameters
    return _SourceAnalysis(
        tree=tree,
        function=function,
        imports_allowed=imports_allowed,
        dangerous_calls_absent=dangerous_calls_absent,
        signature_matches=signature_matches,
    )


def _security_profile_passes(
    *,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expectation: SyntheticVerificationExpectation,
) -> bool:
    if expectation.profile == SyntheticVerificationProfile.SQL_PARAMETERIZED:
        return _sql_parameterization_passes(function, expectation)
    if expectation.profile == SyntheticVerificationProfile.HTML_ESCAPED:
        return _html_escape_passes(function, expectation)
    if expectation.profile == SyntheticVerificationProfile.PATH_CONTAINED:
        return _path_containment_passes(function, expectation)
    raise SyntheticVerificationError("malicious fixture has unsupported verification profile")


def _sql_parameterization_passes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expectation: SyntheticVerificationExpectation,
) -> bool:
    placeholder = expectation.sql_placeholder
    assert placeholder is not None
    parameter = expectation.expected_parameters[-1]
    assignments = {
        target.id: node.value
        for node in function.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in _assignment_targets(node)
    }
    execute_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    ]
    if not execute_calls:
        return False
    for call in execute_calls:
        if len(call.args) < 2:
            return False
        query_node = _resolve_name(call.args[0], assignments)
        if not isinstance(query_node, ast.Constant) or not isinstance(query_node.value, str):
            return False
        if placeholder not in query_node.value:
            return False
        if not _contains_name(call.args[1], parameter):
            return False
    return True


def _html_escape_passes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expectation: SyntheticVerificationExpectation,
) -> bool:
    tainted = expectation.tainted_parameter
    assert tainted is not None
    escape_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _is_escape_call(node)
        and any(_contains_name(argument, tainted) for argument in node.args)
    ]
    if not escape_calls:
        return False
    returns = [node.value for node in ast.walk(function) if isinstance(node, ast.Return)]
    if not returns:
        return False
    return all(
        not _contains_unescaped_name(value, tainted)
        for value in returns
        if value is not None
    )


def _path_containment_passes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expectation: SyntheticVerificationExpectation,
) -> bool:
    root_name = expectation.path_root_name
    tainted = expectation.tainted_parameter
    assert root_name is not None and tainted is not None
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
    has_resolve = any(
        isinstance(call.func, ast.Attribute) and call.func.attr == "resolve" for call in calls
    )
    containment_calls = [
        call
        for call in calls
        if isinstance(call.func, ast.Attribute)
        and call.func.attr in {"relative_to", "is_relative_to"}
    ]
    assignments = {
        target.id: node.value
        for node in function.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in _assignment_targets(node)
    }
    has_containment = any(
        any(
            _contains_name(_resolve_name(argument, assignments), root_name)
            for argument in call.args
        )
        for call in containment_calls
    )
    has_read = any(
        isinstance(call.func, ast.Attribute)
        and call.func.attr in {"read_bytes", "read_text"}
        for call in calls
    )
    has_tainted_input = _contains_name(function, tainted)
    return has_resolve and has_containment and has_read and has_tainted_input


def _functional_contract_passes(
    *,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expectation: SyntheticVerificationExpectation,
) -> bool:
    if any(isinstance(node, ast.Raise) for node in ast.walk(function)):
        return False
    returns = [node.value for node in ast.walk(function) if isinstance(node, ast.Return)]
    if not returns or any(value is None for value in returns):
        return False
    if expectation.profile == SyntheticVerificationProfile.SQL_PARAMETERIZED:
        return all(
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "fetchone"
            for value in returns
        )
    if expectation.profile == SyntheticVerificationProfile.HTML_ESCAPED:
        return True
    if expectation.profile == SyntheticVerificationProfile.PATH_CONTAINED:
        return all(
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr in {"read_bytes", "read_text"}
            for value in returns
        )
    return False


def _module_scaffolding_preserved(
    *,
    original: ast.Module,
    replacement: ast.Module,
    target_function: str | None,
) -> bool:
    if target_function is None:
        return False

    def scaffold(tree: ast.Module) -> tuple[str, ...]:
        rows: list[str] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == target_function:
                    continue
            rows.append(ast.dump(node, include_attributes=False))
        return tuple(rows)

    return scaffold(original) == scaffold(replacement)


def _failed_patch_evidence(
    *,
    fixture_id: str,
    policy_pass: bool,
    reasons: tuple[str, ...],
) -> SyntheticPatchVerificationEvidence:
    return SyntheticPatchVerificationEvidence(
        fixture_id=fixture_id,
        patch_verification_attempted=True,
        patch_policy_pass=policy_pass,
        syntax_startup_pass=False,
        normal_functional_pass=False,
        registered_security_test_pass=False,
        original_replay_pass=False,
        regression_pass=False,
        patch_decision=PatchDecision.REJECTED,
        failure_reasons=reasons,
    )


def _import_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", maxsplit=1)[0])
    return roots


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> tuple[ast.Name, ...]:
    if isinstance(node, ast.Assign):
        return tuple(target for target in node.targets if isinstance(target, ast.Name))
    return (node.target,) if isinstance(node.target, ast.Name) else ()


def _resolve_name(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST:
    if isinstance(node, ast.Name) and node.id in assignments:
        return assignments[node.id]
    return node


def _contains_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))


def _is_escape_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id == "escape"
    return isinstance(call.func, ast.Attribute) and call.func.attr == "escape"


def _contains_unescaped_name(node: ast.AST, name: str, *, escaped: bool = False) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name and not escaped
    if isinstance(node, ast.Call) and _is_escape_call(node):
        return any(_contains_unescaped_name(arg, name, escaped=True) for arg in node.args)
    return any(
        _contains_unescaped_name(child, name, escaped=escaped)
        for child in ast.iter_child_nodes(node)
    )
