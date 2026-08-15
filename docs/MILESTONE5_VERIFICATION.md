# MILESTONE 5 VERIFICATION

## Milestone
**Docker Isolation and Reset**

## Result
**PASS — STATIC AND RUNTIME VERIFICATION COMPLETE**

## Implemented

- `dummy_apps/vulnerable_store/Dockerfile`
- `compose.yaml`
- mandatory `controlled-executor` service
- externally isolated `security-lab` network
- loopback-only dummy-app port
- non-root runtime user
- read-only root filesystems
- dropped capabilities
- `no-new-privileges`
- CPU/memory/PID limits
- named runtime volume
- health checks
- Linux start/reset/isolation scripts
- Windows PowerShell start/reset/isolation scripts
- fixed executor isolation probe
- static Compose/Dockerfile safety tests

## Static Verification

```text
Python compilation: PASS
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
[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m.[0m[32m                          [100%][0m
[32m[32m[1m47 passed[0m[32m in 1.81s[0m[0m
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
compose.yaml structural validation PASS
```

## Development-Machine Runtime Verification

Runtime Docker verification was completed successfully.

Commands executed:

```bash
bash scripts/reset_environment.sh
bash scripts/verify_docker_isolation.sh
docker compose ps
```

Observed result:

```text
Image fyp-red-blue-lab:local: BUILT
Network fyp-red-blue-lab_security-lab: CREATED
Volume fyp-red-blue-lab_store-runtime: CREATED
fyp-vulnerable-store: HEALTHY
fyp-controlled-executor: HEALTHY

PASS: both services are healthy.
PASS: controlled-executor can reach vulnerable-store on the lab network.
PASS: public internet is blocked from controlled-executor.
PASS: Docker lab isolation checks completed.
```

Docker versions recorded:

```text
Docker Engine 29.7.2
Docker Compose v5.4.0
```

## Runtime Gate

**CLOSED**

Milestone 5 Docker isolation is now verified both structurally and at runtime.

## Safety Design

The controlled executor:

- has no published port;
- has no host volume;
- has no Docker socket;
- is non-privileged;
- uses a read-only root filesystem;
- has all Linux capabilities dropped;
- uses `no-new-privileges`;
- is bounded by CPU, memory, and PID limits;
- joins only the `security-lab` network.

The dummy application:

- joins the same internal lab network;
- publishes port 8000 only on host loopback;
- stores mutable runtime data in a named Docker volume.

## Decision

**Milestone 5 is complete.**

Static verification and development-machine Docker runtime verification both
passed. The project may proceed to Milestone 6.

## Next
**Milestone 6 — Target Registry and Policy Engine**
