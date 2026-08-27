# Milestone 14 — Patch Verification Pipeline

## Status

**IMPLEMENTED — automated verification passes in the implementation workspace; authoritative development-laptop GitPython verification and controlled Docker runtime verification remain PENDING.**

Milestone 14 completes the core deterministic remediation loop from an isolated `PatchBranchResult` to an accepted or rejected patch decision. It does not implement automatic retry, merge, push, experiment storage, metrics aggregation, dashboard work, or Milestone 15 functionality.

## Trusted Boundary

The verification path is:

```text
PatchBranchResult + PreparedPatch + confirmed RedTeamRunResult
→ deterministic identity/policy checks
→ exact materialized Git-state validation
→ PATCH_VERIFYING
→ isolated Docker verification
→ deterministic VerificationResult
→ accepted-only local patch-branch commit
→ safe return to unchanged main
```

No LLM participates in verification. No model can choose commands, URLs, regression tests, acceptance criteria, Git operations, or Docker operations.

## Frozen Verification Order

1. patch policy revalidation;
2. path/materialized Git diff validation;
3. syntax and fixed import checks;
4. patched application startup and isolation;
5. fixed normal functional checks;
6. relevant registered security test;
7. exact original confirmed Red Team test replay;
8. trusted regression allowlist;
9. deterministic accept/reject decision.

Structural stages fail closed before unnecessary execution. Once the patched environment is healthy, all four behavioral stages are collected even if one fails so later RQ3 work can use complete structured failure evidence.

## Result Classification

Milestone 14 distinguishes patch quality from trusted infrastructure failures:

```text
PreparedPatch / path / Git-integrity violation → POLICY_BLOCKED
trusted Docker/test-runner infrastructure failure → FAILED
syntax/import/startup/functional/security/replay/regression failure → REJECTED
all mandatory deterministic checks pass → ACCEPTED
```

A patched application that cannot become healthy is a patch failure (`REJECTED`), not an infrastructure escape hatch.

## Verification Policy

Trusted configuration lives at:

```text
config/verification-policy.json
```

It freezes:

- target ID;
- fixed import module;
- one registered verification test per approved vulnerability class;
- exact mandatory regression-test allowlist;
- bounded verification output length;
- health timeout.

The policy covers exactly:

```text
sql_injection → sqli-login-bypass-001
xss → xss-reflection-001
path_traversal → path-traversal-private-file-001
```

The regression allowlist deliberately excludes vulnerability-proving scenario tests such as tests that require SQL injection, raw XSS reflection, or synthetic private-file traversal to remain exploitable.

## Generated-Test Safety

Raw LLM-generated Python tests are **not executed** and do not influence acceptance.

If `PreparedPatch.generated_test_path` exists, Milestone 14 only:

- revalidates its trusted generated-test path;
- verifies its replacement hash;
- includes it in Git-integrity evidence;
- compiles it for Python syntax in the isolated one-shot container.

It is not imported as a test module, passed to pytest, or used as an acceptance criterion. This prevents model-generated Python from gaining code-execution authority and keeps verification identical across RQ1 conditions.

## Git Integrity

`GitService.verify_materialized_patch()` is a new read-only pre-execution check. It requires:

- `PreparedPatch` and `PatchBranchResult` identity equality;
- prepared diff SHA equality;
- exact prepared/changed path equality;
- active recorded patch branch;
- patch-branch HEAD still at the recorded base commit;
- baseline branch unchanged;
- no unstaged or unexpected paths;
- current staged Git diff SHA unchanged;
- every materialized replacement file SHA equal to `PreparedFileChange.replacement_sha256`.

Any drift blocks verification before patched code executes.

## Docker Authority

`services/environment_service.py` exposes only fixed lifecycle operations:

```text
verify_available
build
start
wait_healthy
verify_isolation
cleanup
```

There is no general Docker-command or shell API.

The patched image is built from the active isolated patch branch. Syntax/import runs before application startup using a one-shot:

```text
docker compose run --rm --no-deps controlled-executor ...
```

so Compose cannot start `vulnerable-store` before syntax/import passes.

The live lab is then started only after syntax/import success. Existing Docker hardening remains unchanged: read-only containers, no privilege escalation, dropped capabilities, no Docker socket, and the internal `security-lab` network.

## TestRunner Authority

`services/test_runner.py` exposes named verification operations only:

```text
run_syntax_import
run_functional_checks
run_registered_security_test
run_regression_suite
```

It does not expose arbitrary shell, pytest arguments, container commands, URLs, or HTTP requests.

Live HTTP checks originate only inside `controlled-executor`.

## Functional Checks

`verification/functional.py` performs a fixed bounded set of normal-behavior checks against:

```text
http://vulnerable-store:8000
```

from inside `controlled-executor` only. It covers health, normal login/search/document behavior, plus normal behavior for each scenario route.

## Registered Security and Replay Checks

`infrastructure/executor/run_verification_test.py` is verification-specific and accepts only:

- registered test ID;
- positive attempt number;
- opaque run correlation ID.

It exposes no URL, hostname, method, payload, header, file, or shell input.

The same existing `ControlledExecutor` performs the request. Blue verification inverts the Red evidence meaning:

```text
completed + no exploit evidence → verification PASS
exploit evidence still present → verification FAIL
```

The relevant security stage uses the trusted vulnerability-to-test mapping. The original replay independently executes the exact registered test ID from the confirmed Red run. With the current MVP registry these may be the same test ID, but they remain separate audited executions.

## Regression Checks

The mandatory allowlist contains:

```text
dummy_apps/vulnerable_store/tests/test_baseline.py

dummy_apps/vulnerable_store/tests/test_vulnerability_scenarios.py::test_sql_injection_scenario_keeps_normal_login_behavior
dummy_apps/vulnerable_store/tests/test_vulnerability_scenarios.py::test_xss_scenario_keeps_normal_display_behavior
dummy_apps/vulnerable_store/tests/test_vulnerability_scenarios.py::test_path_traversal_scenario_keeps_public_file_behavior
dummy_apps/vulnerable_store/tests/test_vulnerability_scenarios.py::test_path_traversal_sandbox_blocks_escape_to_host
```

The caller cannot add arbitrary pytest node IDs.

## Acceptance and Git Commit

`verification/decisions.py` accepts only when every required stage passed. There is no LLM confidence, override, or self-approval path.

On `ACCEPTED`, the existing Milestone 13 capability is reused:

```text
GitService.commit_accepted_patch(..., PatchDecision.ACCEPTED)
```

The commit remains local to the isolated `agent-patch/...` branch. `main` is never merged, fast-forwarded, pushed, or mutated.

On `REJECTED`, no patch commit is created.

In all outcomes, Docker cleanup and safe baseline restoration are attempted. Cleanup/restoration failure is surfaced as `FAILED`; unrelated dirty files are never silently erased.

## Auditing

Milestone 14 records bounded audit evidence for:

```text
verification_patch_policy
verification_git_integrity
verification_syntax_import
verification_application_startup
verification_functional
verification_security_test
verification_original_replay
verification_regression
verification_decision
verification_environment_cleanup
workflow_transition
```

Existing Git audit operations continue to record accepted commits and baseline restoration.

## Automated Verification

Implementation-workspace and authoritative development-laptop checks:

```text
Implementation-workspace compilation: PASS
Implementation-workspace full suite after fixture correction: 209 passed, 1 GitPython-only skip
Authoritative GitPython: 3.1.59
Authoritative development-laptop compilation: PASS
Authoritative full suite after fixture correction: 230 passed, 1 warning in 5.67s
Focused patch-generation tests after correction: 21 passed in 0.55s
Focused M14 verification tests after correction: 21 passed
Earlier authoritative schema tests: 20 passed
Earlier authoritative GitService tests: 21 passed
Earlier authoritative M14 verification + schema tests: 41 passed
git diff --check: PASS
```

The warning is the existing Starlette/FastAPI TestClient deprecation warning and is not a milestone failure.

The first Docker runtime attempt exposed a deterministic Path Traversal fixture regression: the generated remediation intercepted host-sandbox escape at the new `intended_public_root` guard and changed the trusted response from `"Scenario sandbox escape blocked"` to `"Path traversal blocked"`. The verifier correctly rejected that patch at the mandatory regression stage. The correction was deliberately limited to `llm/mock_provider.py` and `tests/test_patch_generation.py`: the existing `scenario_root` sandbox guard remains first, followed by the new `intended_public_root` containment guard. The regression policy/test was not weakened.

## Controlled Host-Side Docker/Git Runtime Verification

**PASS — complete corrected runtime verification completed on 2026-08-27.**

The corrected runtime used disposable repositories rooted at temporary runtime baseline:

```text
ee535c199907556c6797d375c42f3ec458dfae3e
```

Positive accepted-remediation evidence:

```text
SQL Injection: ACCEPTED; local patch-branch commit a8e0d1a93ede0e2dd0270cc55c82774291ed717a
XSS + hostile raw generated-test guard: ACCEPTED; local patch-branch commit 3961b3035683e6dd06b38c4db5087f7d0674a612
Path Traversal after deterministic fixture correction: ACCEPTED; local patch-branch commit de2ad5647b903646e0c576d123cda3e7169b10d3
```

Before those cases, the unpatched disposable baseline was independently confirmed vulnerable for all three registered tests.

Negative/fail-closed evidence:

```text
Policy-valid insecure XSS patch: REJECTED by security + original replay
Security-fixing but behavior-breaking XSS patch: REJECTED by functional/regression
Invalid Python patch: REJECTED at syntax/import before application startup
Staged Git diff drift: POLICY_BLOCKED before Docker verification stages
```

Generated-test safety evidence:

```text
Hostile raw generated test: compiled successfully
Raw generated test imported/collected/executed: NO
Influence on ACCEPTED/REJECTED decision: NO
Permanent generated-test write: NO
```

Isolation, Git and cleanup evidence:

```text
All seven disposable case repositories ended on clean main at ee535c1: PASS
Accepted remediation commits exist only on local agent-patch branches: PASS
Rejected/POLICY_BLOCKED attempts have no accepted remediation commit: PASS
Docker post-verification service list empty: PASS
Permanent scenario_routes.py SHA-256 unchanged: PASS
All 24 permanent Milestone 14/correction files unchanged: PASS (24/24)
Permanent branch refs before/after identical: PASS
Permanent porcelain status before/after identical: PASS
Permanent repository branch remained main: PASS
Permanent HEAD remained 7d883b80639a3cc12d354cd6fcee29c1dbf6e174: PASS
Permanent agent-patch branches: none
Final Git-visible scope: exactly 24 Milestone 14/correction paths
git diff --check after runtime verification: PASS
```

No automatic merge, remote push, or Milestone 15 behavior was performed. Milestone 14 is technically verified; final documentation/staged Git review and the milestone commit remain pending.

## Milestone Boundary

Milestone 14 deliberately does not implement:

- automatic retry / RQ3 feedback execution;
- experiment persistence;
- metrics aggregation;
- dashboard/UI;
- automatic merge;
- remote Git publication;
- real external LLM provider integration;
- new vulnerability classes.

Those remain later milestones.
