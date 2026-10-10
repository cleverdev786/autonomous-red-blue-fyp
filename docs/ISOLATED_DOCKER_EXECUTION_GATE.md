# Isolated Docker Registered Execution Seam

**Gate:** Gate 2, source implementation and offline testing only, 2026-10-10.

## Scope

The new source is services/isolated_compose_executor.py with tests in
tests/test_isolated_compose_executor.py. It is independent of the frozen,
mock-only services/isolated_compose_mock_adapter.py and its historical receipts.

This module implements a future **explicitly admitted real process seam**:
IsolatedDockerExecutor.run_registered() can run exactly one registered
baseline test through the existing infrastructure.executor.run_verification_test
and trusted ControlledExecutor policy/evaluator. It cannot issue user-supplied
URLs, payloads or shell commands, invoke agents/models, apply patches,
retry automatically, operate container lifecycle/cleanup, or run final research.
It launches no subprocess on import or construction (construction validates\nthe external admission file).

## Required future live authorization

Before any future live invocation, an operator must separately approve:
- An independently reviewed external canonical RealExecutionAdmission file
  with SHA-256 communicated separately from the file.
- A clean integration-branch source checkout at the explicitly pinned
  Git HEAD/tree and pinned hashes of all critical source/configuration files.
  The source must be independently reviewed and pinned after the local Gate 3
  commit. A local commit by itself is not runtime authorization.
- Independently validated provenance tying a separately authorized image
  build to the approved source; its image ID, Docker daemon ID and both
  running container IDs must be pinned in the external admission.
- Verified exclusive ownership and healthy state of both isolated
  containers, dedicated project/network, resource limits, restrictions,
  127.0.0.1:18080 binding, and exact in-container source-file hashes.
- Explicit one-case/one-run development-only authorization to dispatch
  one of the three registered deterministic tests, with outside-repository
  evidence parent already created.

**Limitation:** Matching selected source files inside containers and a
pinned image ID does not by itself prove the entire image was built from
the admitted Git tree. The independent build provenance remains a separate
required gate. A self-written manifest or checksum is not authorization.

## Fail-closed implementation

The adapter verifies Git HEAD/tree, clean branch, frozen Compose YAML,
normalized effective Compose configuration, Docker context/daemon/image
identity, Compose labels, bridge network ownership and membership, isolated
image and volume Compose ownership, running container health, mounts, read-only
protections, port binding, CPU/memory/PID
limits, and approved source-file hashes both on host and in each container.\nThe default binary runner streams process output within fixed byte limits and\nuses per-command deadlines; it kills a process that exceeds the limits.

It retains dispatch-intent.json, bounded byte-preserving stdout.raw and
stderr.raw, receipt.json and, only on trusted parse, observation.json, in
an exclusive external case directory. Identity is rechecked after the single
dispatch. Nonzero, timeout, forged, drifted or unparseable evidence never
counts as confirmed; a case is never auto-redispatched.

These checks are **implemented but not live-validated**. Current tests
inject all Git/Docker/process responses, using a fake HTTP transport to
exercise the actual ControlledExecutor Python logic without network traffic.

## Next approval boundary

After Gate 3 source review/local commit, independently pin the committed
source version and approve an image-build plan. After separately authorized
image building and live Docker resource checks, seek a new explicit approval
for any registered container execution. No live Docker operation is authorized
by Gate 2 or Gate 3.
