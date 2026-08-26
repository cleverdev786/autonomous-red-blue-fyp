# Milestone 13 — Git Automation and Patch Branch Isolation

## Status

**TECHNICALLY VERIFIED — authoritative automated verification with GitPython and controlled host-side Git runtime verification PASS; final staged Git review and commit PENDING.**

Milestone 13 materializes an already policy-approved Milestone 12 `PreparedPatch` onto one deterministic local Git patch-attempt branch. It does not run patch verification, decide patch acceptance, merge into `main`, or publish anything remotely.

## Authority Boundary

```text
PatchGenerationResult
        ↓
PreparedPatch (trusted Milestone 12 artifact)
        ↓
PatchBranchFlow (trusted orchestrator)
        ↓
GitService (restricted deterministic local Git service)
        ↓
isolated patch-attempt branch + bounded Git diff evidence
        ↓
PATCH_APPLYING

STOP
```

Milestone 13 has no LLM/provider call. No agent receives Git, shell, Docker, filesystem, or remote-publishing authority.

## Trusted Git Policy

Human-controlled repository policy lives in:

```text
config/git-policy.json
```

Current policy:

```json
{
  "baseline_branch": "main",
  "patch_branch_prefix": "agent-patch"
}
```

`GitPolicyConfig` rejects unsafe Git-ref syntax and keeps the baseline outside the patch namespace.

Patch branch names are generated deterministically by the trusted service:

```text
agent-patch/<run_id>/attempt-<attempt_number>
```

For example:

```text
agent-patch/m13-runtime-xss/attempt-1
```

The caller does not supply a free-form patch branch name.

## Baseline Validation

Before branch creation, `GitService.verify_clean_baseline()` requires:

1. a valid local Git repository;
2. the configured baseline branch to be checked out;
3. no staged, unstaged, or non-ignored untracked changes;
4. an exact expected baseline SHA when the trusted caller supplies one.

A dirty or unexpected baseline fails closed before branch creation.

## Branch Creation Before Any Patch Write

`GitService.create_patch_branch()` rechecks that:

- the configured baseline is still active;
- the repository is still clean;
- `HEAD` still equals the recorded base commit;
- the deterministic attempt branch does not already exist.

Only then is the local patch branch created and checked out.

A branch-name collision is blocked rather than silently reused or overwritten.

## PreparedPatch Is the Only Patch Input

Milestone 13 consumes:

```text
PreparedPatch
```

It does not consume raw `PatchProposal` output and does not ask an LLM to regenerate patch contents.

Before any file write, the service revalidates:

- `PreparedPatch.unified_diff` SHA-256;
- every replacement-content SHA-256;
- unique prepared paths;
- every path through `PolicyEngine.validate_patch_path()`;
- absence of symlink patch targets;
- existing-source SHA-256 against `PreparedFileChange.original_sha256`;
- nonexistence of prepared new files;
- empty original hash for prepared new files.

These checks protect against stale or tampered prepared artifacts.

## Exact-Path Materialization

After all files pass preflight, the service writes only:

```text
PreparedPatch.files[].file_path
```

and verifies the resulting SHA-256 of every written file.

The exact approved paths are then staged locally on the isolated patch branch. Staging is used only to obtain a complete bounded native Git diff, including optional generated test files. It is not a commit and does not alter the baseline branch.

After staging, the service requires:

- Git's changed-path set to equal the prepared path set exactly;
- no remaining unstaged or unexpected untracked changes;
- a non-empty bounded native Git diff.

The resulting evidence records both:

```text
PreparedPatch.diff_sha256
git_diff_sha256
```

These hashes are not required to be equal because Milestone 12 and Git use different diff encodings. Equivalence is instead enforced through exact changed paths and replacement-content hashes.

## Typed Result

`PatchBranchResult` records:

```text
run_id
target_id
attempt_number
baseline_branch
base_commit
branch_name
prepared_diff_sha256
git_diff
git_diff_sha256
changed_paths
final_state
```

A successful Milestone 13 flow ends at:

```text
PATCH_APPLYING
```

It deliberately does not claim the patch is secure, accepted, or regression-safe.

## Transactional Failure Handling

Patch materialization snapshots only the prepared paths before writing.

If an application step fails after writes begin, rollback:

- restores previously existing prepared files from their exact original bytes;
- removes only prepared new files;
- resets the Git index only for those exact prepared paths.

Milestone 13 does not use broad destructive cleanup such as:

```text
git reset --hard
git clean -fd
```

as normal recovery behavior.

Unrelated developer files are never silently erased.

## Safe Baseline Restoration

`GitService.restore_baseline()` works only from the recorded patch branch.

Before restoration it checks for unrelated dirty paths. If an unrelated path exists, restoration fails closed rather than deleting it.

For the known prepared paths it restores the recorded baseline content/absence state, resets only those paths in the index, requires the patch branch to become clean, then checks out the configured baseline branch.

Final restoration requires:

```text
baseline HEAD == recorded base commit
working tree clean
```

Patch branches are retained for later research/forensic inspection; Milestone 13 does not automatically delete them.

## Accepted-Patch Commit Capability

`GitService.commit_accepted_patch()` exists for the later verification workflow, but `PatchBranchFlow` does not call it in Milestone 13.

The method requires an explicit trusted:

```text
PatchDecision.ACCEPTED
```

and rejects `PatchDecision.REJECTED`.

Before a local commit it additionally requires:

- the recorded patch branch to be active;
- the baseline branch to remain unchanged at the recorded base SHA;
- no prior patch-branch commit drift;
- exact recorded changed paths;
- no unstaged changes;
- the current staged Git diff SHA-256 to equal `PatchBranchResult.git_diff_sha256`.

The commit message is deterministic and service-generated:

```text
Patch attempt <run_id> attempt <attempt_number>
```

The capability creates only a local patch-branch commit. It never merges or pushes.

## Explicitly Absent Git Authority

`GitService` intentionally exposes no method for:

```text
push
force_push
merge
pull
fetch
run_git
execute_command
```

Milestone 13 introduces no remote Git operation and no agent-controlled Git interface.

## Audit Coverage

Sensitive Git actions are recorded through the existing `AuditService`:

```text
git_baseline_validation
git_branch_creation
git_patch_materialization
git_diff_inspection
git_restore_baseline
git_accepted_patch_commit
workflow_transition
```

Successful evidence references use bounded identifiers/hashes such as:

```text
base commit SHA
PreparedPatch diff SHA-256
Git diff SHA-256
accepted local commit SHA
```

Blocked operations receive stable service error codes and fail closed.

## Workflow Boundary

Milestone 13 uses the existing deterministic state transitions:

```text
PATCH_VALIDATING
→ PATCH_BRANCH_CREATING
→ PATCH_APPLYING
```

It stops at `PATCH_APPLYING`.

Milestone 14 owns:

```text
PATCH_APPLYING
→ PATCH_VERIFYING
```

and the later syntax/startup/functional/security/replay/regression acceptance pipeline.

## Research Impact

### RQ1

The Git service is shared deterministic infrastructure. Future single-general and specialized-multi-agent Blue conditions must use the same branch isolation and Git policy so Git behavior does not become a confounding variable.

### RQ2

Milestone 13 runs after classification and does not modify the `rule_only`, `llm_only`, or `hybrid` classification pathways.

### RQ3

Branch names include `run_id` and `attempt_number`, allowing separate future retry attempts such as:

```text
agent-patch/run-123/attempt-1
agent-patch/run-123/attempt-2
```

Milestone 13 does not decide whether a retry occurs and does not generate verification feedback.

### Ground-Truth Separation

The Git service receives an already prepared artifact and bounded operational metadata. It exposes no generic history browsing or repository-reading capability to an LLM.

## Automated Verification

The implementation adds temporary-repository coverage in:

```text
tests/test_git_service.py
```

The tests cover:

- clean baseline validation;
- wrong baseline branch rejection;
- dirty baseline rejection;
- exact expected base-SHA rejection;
- deterministic branch naming;
- branch collision rejection;
- baseline-write rejection;
- source SHA drift rejection;
- generated-test materialization on the patch branch;
- exact-path restoration;
- refusal to erase unrelated dirty files;
- explicit `PatchDecision.ACCEPTED` local commit gating;
- rejection of commit after diff drift;
- tampered prepared-diff rejection;
- duplicate prepared-path rejection;
- transactional rollback after a synthetic second-write failure;
- invalid workflow-state rejection;
- absence of push/merge/force-push/arbitrary-command methods.

Authoritative permanent development-laptop verification observed:

```text
GitPython: 3.1.59
Python compilation: PASS
Full suite: 203 passed, 1 warning in 11.06s
Focused Milestone 13 Git suite: 19 passed in 4.53s
Schema suite: 17 passed in 0.21s
git diff --check: PASS
prohibited Git-interface grep: PASS (no matches)
destructive reset/clean grep: PASS (no matches)
final branch: main
final HEAD: ff17026
final source scope: exactly 10 Milestone 13 paths
```

The single pytest warning is the existing Starlette/FastAPI TestClient deprecation warning and did not fail the suite. The earlier implementation-workspace compatibility-shim run is superseded by this authoritative result using the project's real GitPython dependency.

## Controlled Host-Side Git Runtime Verification

Runtime verification was performed on 2026-08-26 with the permanent repository providing the current Milestone 13 implementation while all Git-mutating scenarios ran only inside disposable `/tmp` clones of the committed `ff17026` baseline.

Observed results:

```text
disposable clones started clean on main @ ff17026: PASS
PreparedPatch materialized only on agent-patch/m13-runtime-xss/attempt-1: PASS
baseline main remained ff17026: PASS
native Git diff SHA-256: f767123700a56fd9320174e35f0b5624ba283675a21b792538429f07c9396035
exact-path restoration returned to clean main: PASS
patch-attempt branch retained: PASS
generated security test existed only on disposable patch branch: PASS
generated security test removed during exact-path restoration: PASS
dirty baseline blocked: PASS
wrong expected base SHA blocked: PASS
deterministic branch collision blocked: PASS
direct materialization on main blocked: PASS
PatchDecision.REJECTED commit blocked: PASS
PatchDecision.ACCEPTED local patch-branch commit created: 3d149c001c02df1dccae9bc38961adf3ad041499
accepted commit did not move main: PASS
permanent scenario_routes.py SHA-256 unchanged: PASS
permanent branch refs unchanged: PASS
permanent repository remained main @ ff17026: PASS
permanent changed/untracked scope remained exactly 10 Milestone 13 paths: PASS
git diff --check after runtime verification: PASS
```

The accepted-commit disposable clone retained the normal local `origin` created by `git clone`, pointing at the permanent repository. No push, merge, force-push, fetch-driven mutation, or other remote publication occurred. The runtime gate therefore verifies the local capability without changing the permanent baseline.

## Still Locked

Milestone 13 does not implement:

- patch syntax verification;
- patched application startup;
- generated security-test execution;
- original attack replay;
- regression tests against a patched target;
- acceptance/rejection orchestration;
- automatic patch retry;
- automatic merge;
- remote push or publication;
- Milestone 14 verification logic.

## Next Gate

Complete the final staged Git review and Milestone 13 commit. The staged scope must remain exactly the verified 10 files and pass `git diff --cached --check`.

Do not merge or push any patch-attempt branch and do not begin Milestone 14 until the Milestone 13 commit is confirmed.
