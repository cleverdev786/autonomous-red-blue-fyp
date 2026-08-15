# MILESTONE 2 VERIFICATION

## Milestone
**Core Schemas and Configuration**

## Result
**PASS**

## Verification Commands

```bash
PYTHONDONTWRITEBYTECODE=1 python -m compileall -q orchestrator schemas services llm
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q
```

## Results

```text
Compilation: PASS
Spreadsheet runtime warmup failed during python startup
Traceback (most recent call last):
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/patches/warm_spreadsheet_runtime_on_startup.py", line 26, in warm_spreadsheet_runtime_on_startup
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/spreadsheet_warmup.py", line 785, in warm_spreadsheet_runtime
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/spreadsheet_warmup.py", line 720, in _warm_feature_flows
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/spreadsheet_warmup.py", line 704, in _warm_collaboration_flows
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/generated/interface/models.py", line 32317, in hydrate_crdt_from_proto
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/rpc/remote.py", line 749, in __call__
  File "/tmp/tmp.L2TH2Y5coc/artifact_tool_v2-2.8.22/artifact_tool/rpc/client.py", line 150, in call
artifact_tool.rpc.client.RemoteError: hydrateCrdtFromProto requires an empty collaborative document.
[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m                                                          [100%][0m
[33m=============================== warnings summary ===============================[0m
../../../opt/pyvenv/lib/python3.13/site-packages/_pytest/cacheprovider.py:475
  /opt/pyvenv/lib/python3.13/site-packages/_pytest/cacheprovider.py:475: PytestCacheWarning: cache could not write path /mnt/data/autonomous-red-blue-fyp/.pytest_cache/v/cache/nodeids: [Errno 13] Permission denied: '/mnt/data/autonomous-red-blue-fyp/.pytest_cache/v/cache/nodeids'
    config.cache.set("cache/nodeids", sorted(self.cached_nodeids))

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
[33m[32m15 passed[0m, [33m[1m1 warning[0m[33m in 0.08s[0m[0m
```

## Schema Modules

```text
schemas/common.py
schemas/targets.py
schemas/red_team.py
schemas/blue_team.py
schemas/patches.py
schemas/verification.py
schemas/experiments.py
```

## Verified Invariants

1. Only SQL Injection, XSS, and Path Traversal are valid MVP vulnerability categories.
2. RQ2 classification labels are frozen.
3. External-URL-style endpoint paths are rejected.
4. Parent-directory target path escape is rejected at schema level.
5. Extra actionable fields are rejected.
6. Obvious patch path escape is rejected.
7. Policy decisions cannot contradict their reason code.
8. A required verification-stage failure prevents patch acceptance.
9. Final RQ1/RQ2 configurations cannot enable exploratory experience-guided selection.
10. Schema JSON serialization/deserialization round-trips successfully.
11. Existing repository-foundation tests still pass.

## Boundary

Schema validation checks structure and basic invariants. It does **not** authorize operations.

The future policy engine must still determine whether:

- a target is actually registered;
- an endpoint/method is allowlisted;
- a test ID exists;
- a canonical file path is inside an approved root;
- a patch is within writable roots and size limits;
- the workflow state permits the action.

## Decision
**Milestone 2 is complete.**

## Next Milestone
**Milestone 3 — Dummy Application Baseline**

The next milestone creates only normal application functionality and functional tests. Deliberate vulnerabilities are introduced afterward.
