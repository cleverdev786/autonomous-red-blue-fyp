# MILESTONE 3 VERIFICATION

## Milestone
**Dummy Application Baseline**

## Result
**PASS**

## Objective
Establish a normal functional application before deliberately introducing the three controlled vulnerability scenarios.

## Implemented Features

- FastAPI application factory
- SQLite + SQLAlchemy
- deterministic synthetic seed/reset
- normal health endpoint
- normal JSON login
- normal product search
- normal document listing
- safe document download by database ID

## Synthetic Accounts

```text
student1 / demo-pass-1
student2 / demo-pass-2
```

These credentials are fabricated for the local dummy application only.

## Baseline Security/Regression Properties

At this milestone:

- login is not built from raw SQL strings;
- search uses SQLAlchemy-bound expressions;
- search output is JSON rather than reflected HTML;
- file download does not accept a caller-supplied path;
- resolved document files are restricted to the seed directory.

This is intentional. The project needs a known-good baseline before the next milestone creates controlled vulnerable variants.

## Verification Commands

```bash
PYTHONDONTWRITEBYTECODE=1 python -m compileall -q orchestrator schemas services llm dummy_apps
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
```

## Test Output

```text
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
[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m                                               [100%][0m
[32m[32m[1m26 passed[0m[32m in 1.65s[0m[0m
```

## Decision
**Milestone 3 is complete.**

## Next Milestone
**Milestone 4 — Deliberate Vulnerability Scenarios**

The next milestone will add exactly one controlled, local scenario for SQL Injection, XSS, and Path Traversal with matching deterministic security tests and ground-truth records.
