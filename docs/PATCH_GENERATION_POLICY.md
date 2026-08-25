# Milestone 12 — Patch Generation and Patch Policy

## Status

**TECHNICALLY VERIFIED — implementation, automated verification, and host-side development-laptop runtime verification PASS; final staged Git review and commit PENDING.**

Milestone 12 converts a validated Milestone 11 `CodeFinding` into a deterministic, policy-approved **in-memory** patch artifact. It deliberately stops before Git branch creation, file application, patched-application execution, or patch acceptance. Those responsibilities remain Milestones 13 and 14.

## Authority Boundary

```text
BlueTeamAnalysisResult
        ↓
PatchGenerationAgent
        ↓
PatchProposal (untrusted)
        ↓
Pydantic + orchestrator identity checks
        ↓
PolicyEngine path/size decisions
        ↓
PatchService (trusted deterministic service)
        ↓
PreparedPatch (in memory only)
        ↓
PATCH_VALIDATING

STOP
```

The Patch Generation Agent receives no direct shell, filesystem-write, Docker, network, Git, or arbitrary-command authority.

## Grounded Exact-Text Edits

`ProposedFileChange` now contains:

```text
file_path
original_content
replacement_content
rationale
```

The deterministic Patch Service accepts a source edit only when:

1. its path exactly matches the validated `CodeFinding.file_path`;
2. `original_content` was present in the bounded source context supplied to the agent;
3. `original_content` occurs exactly once in the current source file;
4. multiple proposed edits do not overlap;
5. the path passes `PolicyEngine.validate_patch_path()`;
6. the final diff remains inside configured patch-size limits.

The agent therefore does not reconstruct or replace an entire file from partial context.

## Bounded Patch Context

`PatchGenerationFlow` starts only from a `BlueTeamAnalysisResult` ending in:

```text
code_analysis
```

and requires a validated `CodeFinding` with supporting source lines.

A fresh `SourceReader` context is prepared for exactly the localized application file. The context contains a small header/import region plus a bounded region around the cited finding. Existing Milestone 11 restrictions still apply, including exclusion of scenario ground truth and non-application source.

The agent input contains only:

- `TriageResult`;
- `CodeFinding`;
- bounded approved source snippets;
- the requested patch attempt number;
- deterministic patch constraints;
- optional `PatchRetryFeedback` when explicitly supplied.

It does not receive Red attack plans/execution results, registered security-test metadata, scenario ground-truth JSON, or direct filesystem handles.

## Patch Proposal and Prepared Patch Separation

`PatchProposal` is an untrusted reasoning output.

`PreparedPatch` is the trusted deterministic result after grounding and policy checks.

`PreparedPatch` records:

- run and target identity;
- patch attempt number;
- prepared file contents and source/replacement SHA-256 values;
- a unified diff;
- unified-diff SHA-256;
- files changed;
- inserted/deleted line counts;
- total diff bytes;
- optional service-derived generated-test path.

No generated source or test is written to the repository in Milestone 12.

## Human-Controlled Patch Limits

The trusted target configuration now contains:

```json
"patch_limits": {
  "max_files_changed": 2,
  "max_inserted_lines": 120,
  "max_deleted_lines": 120,
  "max_total_diff_bytes": 20000
}
```

The two-file limit represents the intended maximum Milestone 12 patch shape:

```text
1 localized application source file
+
1 optional generated security-test file
```

`PolicyEngine.validate_patch_size()` fails closed with `patch_too_large` when any configured limit is exceeded.

Generated patch paths are additionally restricted to Python (`.py`) files under the target's approved writable roots.

## Optional Generated Security Test

The LLM may propose:

```text
ProposedSecurityTest
```

but does not control the destination path.

`test_name` must match:

```text
test_[A-Za-z0-9_]+
```

The trusted Patch Service derives the destination from the target's configured generated-test writable root:

```text
dummy_apps/vulnerable_store/tests/generated/<test_name>.py
```

The derived path is then independently checked through the deterministic patch-path policy.

The proposed test remains part of the in-memory patch only. It is not executed in Milestone 12.

## Deterministic Diff Preparation

The Patch Service uses Python standard-library functionality only:

```text
difflib.unified_diff
hashlib.sha256
```

No new dependency was added.

Milestone 12 exposes no method for:

```text
apply_patch
write_file
git_apply
commit
merge
run_command
```

Git branch isolation belongs to Milestone 13. Patch execution and deterministic acceptance/rejection belong to Milestone 14.

## Workflow and Budgets

The flow requires and records the transitions:

```text
CODE_ANALYSIS
→ PATCH_GENERATING
→ PATCH_VALIDATING
```

It stops at `PATCH_VALIDATING`.

Before model invocation it checks and consumes:

- one patch-attempt budget;
- one model-call budget.

Budget denial occurs before the provider receives the request.

## RQ3 Preparation

`PatchGenerationFlow.run()` accepts:

```text
PatchRetryFeedback | None
```

When absent, no retry-feedback field is included in the model input.

When supplied, only the typed structured feedback is included.

Milestone 12 does **not** implement the retry loop or produce verification feedback. This preserves the later RQ3 comparison without implementing Milestone 14 prematurely.

## Audit Coverage

Milestone 12 records bounded audit events for:

```text
patch_attempt_authorization
model_call_authorization
model_call
patch_path_validation
patch_size_validation
patch_prepare
workflow_transition
```

Successful patch preparation stores the diff SHA-256 as the evidence reference rather than storing a second full copy of the source diff in the audit log.

Blocked policy/grounding preparation attempts are recorded as blocked events.

## Automated Verification

Implementation-workspace automated verification:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python -m pytest -q -p no:cacheprovider

python -m pytest -q -p no:cacheprovider tests/test_patch_generation.py
```

Observed result:

```text
Python compilation: PASS
Full pytest suite: 180 passed
Focused Milestone 12 tests: 20 passed
```

Coverage includes:

- all three approved vulnerability findings produce grounded prepared patches;
- patch preparation changes no application source on disk;
- optional generated-test path is service-derived and remains unwritten;
- ground-truth/Red execution artifacts are absent from patch-agent input;
- retry feedback is included only when supplied;
- patch/model budgets fail before provider invocation;
- invalid workflow state or missing `CodeFinding` is rejected;
- run identity mismatch is rejected;
- absent/ungrounded anchors are rejected;
- edits to files other than the validated finding file are rejected;
- protected paths fail closed;
- oversized patches fail with `patch_too_large`;
- non-Python files inside writable roots are rejected;
- configured valid patch sizes are accepted;
- unsafe generated-test names are rejected;
- patch-preparation audit evidence contains the diff hash.


## Host-Side Runtime Verification

Development-laptop runtime verification completed successfully on 2026-08-25 from the permanent repository while `main` remained at Milestone 11 commit `a3421a2`.

The runtime gate deliberately avoided Docker, Git branch creation, patch application, generated-test writes, or patched-application verification. It exercised the actual `PatchGenerationFlow` and trusted `PatchService` against the real committed vulnerable application source and retained audit evidence under `/tmp` only.

Observed prepared-patch results:

```text
SQL Injection
files=1
inserted=7
deleted=4
total_diff_bytes=958
diff_sha256=66269f75a26c4350d79b2dac654c47285e1d6a42f967ee4af9cbd9a88af3bfb5

XSS
files=1
inserted=2
deleted=1
total_diff_bytes=606
diff_sha256=a86c1f805bd497e2610f5c65088a32d3387af0ad407ac8eeb57e9b93410483c0

Path Traversal
files=1
inserted=9
deleted=0
total_diff_bytes=964
diff_sha256=c0c0e531670dd9bfcf1fb7db5c759d649e8b2aee25685f147629a0008d88fa6c
```

The runtime gate also confirmed:

```text
optional generated security test remained in memory only: PASS
orchestrator/policy_engine.py patch path blocked: PASS
.env patch path blocked: PASS
mandatory baseline test patch path blocked: PASS
oversized patch blocked with deterministic policy: PASS
ungrounded exact-text replacement blocked and audited: PASS
scenario_routes.py hash unchanged after all runtime checks: PASS
generated security test not written: PASS
branch remained main: PASS
HEAD remained a3421a2: PASS
git diff --check: PASS
Milestone 12 changed/untracked scope unchanged: PASS
```

This runtime evidence demonstrates that Milestone 12 can produce bounded, policy-approved in-memory remediation artifacts for all three approved vulnerability classes without modifying the baseline or crossing into Milestone 13 Git automation or Milestone 14 verification.

## Remaining Gate

Milestone 12 is **technically verified but not permanently complete yet**.

Completed:

1. implementation on the permanent development repository;
2. compilation and full/focused automated verification;
3. host-side in-memory patch-preparation runtime verification;
4. documentation finalization with actual laptop evidence.

Still required:

1. complete final staged Git review of the exact 16-file Milestone 12 scope;
2. commit Milestone 12;
3. confirm a clean working tree after commit.

Do not begin Milestone 13 until these gates close.
