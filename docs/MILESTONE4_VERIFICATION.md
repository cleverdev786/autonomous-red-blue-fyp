# MILESTONE 4 VERIFICATION

## Milestone
**Deliberate Vulnerability Scenarios**

## Result
**PASS**

## Implemented Scenarios

### SQL Injection

```text
Scenario ID: sqli-login-001
Test ID: sqli-login-bypass-001
Endpoint: POST /scenarios/sql-injection/login
```

The scenario intentionally constructs a SQL statement from the synthetic
`username` input.

The normal `/login` route remains separate and continues to reject the same
injection-style input.

### Reflected XSS

```text
Scenario ID: xss-search-001
Test ID: xss-reflection-001
Endpoint: GET /scenarios/xss/search
```

The scenario intentionally reflects `q` into an HTML response without output
encoding.

The normal `/search` route remains a JSON data flow.

### Path Traversal

```text
Scenario ID: path-traversal-read-001
Test ID: path-traversal-private-file-001
Endpoint: GET /scenarios/path-traversal/read
```

The route intends to serve files from:

```text
scenario_files/public/
```

but deliberately permits traversal into:

```text
scenario_files/private/
```

inside the synthetic lab filesystem.

A separate outer containment check still prevents the resolved path from
escaping the complete `scenario_files/` directory. This preserves the
educational vulnerability while preventing arbitrary host-file access.

## Ground Truth

Three JSON ground-truth manifests validate against `ScenarioGroundTruth`.

They record:

- scenario/test IDs;
- vulnerability class;
- endpoint/method/input;
- vulnerable source file/function;
- root cause;
- expected evidence;
- secure behavior;
- normal behavior;
- baseline reference;
- reset operation.

## Verification Commands

```bash
PYTHONDONTWRITEBYTECODE=1 python -m compileall -q orchestrator schemas services llm dummy_apps
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
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
[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m                                    [100%][0m
[32m[32m[1m37 passed[0m[32m in 1.79s[0m[0m
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
3 scenario manifests validated
```

## Safety Result

- All tests use the self-created dummy application.
- Scenario tests run through an in-process FastAPI TestClient.
- No external target is used.
- No Red/Blue LLM agent exists yet.
- No unrestricted HTTP executor exists yet.
- No arbitrary shell tool is exposed.
- The traversal scenario cannot escape the synthetic scenario sandbox.
- Baseline routes remain covered by functional/regression tests.

## Decision
**Milestone 4 is complete.**

## Next Milestone
**Milestone 5 — Docker Isolation and Reset**
