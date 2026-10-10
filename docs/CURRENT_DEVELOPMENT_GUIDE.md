# Current Development Guide

**Updated:** 2026-10-09

## Main working repository

The primary project is at `/home/zain/Documents/RED FYP/autonomous-red-blue-fyp`.
The current integration branch is `integration/r4c4f-primary-20261009`.
It contains the existing FYP foundation, four unchanged historic R3/R4
development commits, and the isolated Compose/mock-adapter integration.

The original recovery and M20 branches have been preserved. There has been
**no merge into `main`**. Separate old R4 sandboxes and experiment Git
checkouts are archived references, not the active development repository.

## Why there are two YAML files

| File | Scope | Host endpoint |
|---|---|---|
| `compose.yaml` | Original/legacy FYP Docker configuration with historic fixed names and the old image tag | `127.0.0.1:8000` |
| `compose.isolated.yaml` | **Standalone** isolated Compose configuration with independent project, image, container, network and volume identities | `127.0.0.1:18080` |

The container's internal port remains 8000. These files should **not** be
combined with multiple `-f` arguments: the isolated file is complete, not a
partial override. The original Docker images/containers are historical
resources and must not be automatically pruned, overwritten or cleaned up.

The original `EnvironmentService` and `TestRunner` still target the legacy
Compose configuration. The `services/isolated_compose_mock_adapter.py`
module only constructs and verifies intended commands against **injected
mock runners**. It does not call Docker, attest a live container, or perform
Red testing.

A separately gated real execution seam is now implemented in
services/isolated_compose_executor.py. Its source and offline test
boundary are described in docs/ISOLATED_DOCKER_EXECUTION_GATE.md.
It has not been executed against real Docker containers.

## Descriptive module organization

- `schemas/registered_red_observation.py`: typed registered Red observations.
- `schemas/execution_admission.py`: externally pinned mock admission contract.
- `schemas/readiness_request.py`: filesystem/Git/Docker admission request.
- `services/security_preflight.py`: registered-test offline preflight checks.
- `services/executor_evidence_capture.py`: raw binary evidence collector contract.
- `services/environment_readiness.py`: Git and Docker readiness simulation.
- `services/runtime_evidence_contract.py`: simulated runtime identity binding.
- `services/readiness_guards.py`: filesystem, Git and Docker safety guards.
- `services/isolated_compose_mock_adapter.py`: isolated Compose command planning.

Automated tests use corresponding `tests/test_<module>.py` names. Evidence
protocol/schema version identifiers such as `r4c4f-...` and historical
manifest references are intentionally retained because changing those
would break provenance rather than simply clean up file naming.

## Local development and tests

Run the offline suite from the project root:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -B -m pytest -q -p no:cacheprovider
```

This suite uses mocks and temporary fixtures. It does **not** prove the
current integrated release can run Docker safely. The first live Docker step
is a separately authorized read-only effective Compose config and
resource/port audit. Do not run `docker compose up`, `down`, `build` or
`prune` from this guide.

## Status and remaining FYP work

- M1–M19: historically completed; the August 2026 controlled remediation
  demonstration belongs to that historical evidence.
- M20: official Q6_K DEVELOPMENT feasibility result remains **INELIGIBLE**
  (2 of 6 accepted patches). No rerun of that frozen exposure is permitted.
- Current integrated code: offline development and source integration done,
  real runtime-bound Red evidence for this version still to be proved.
- M21: final RQ1/RQ2 experiments **BLOCKED** pending a defensible model and
  frozen experimental protocol. The minimum design requires 18 RQ1 runs
  and 60 labeled events across three RQ2 classifier conditions.
- M22–M25: results analysis, final academic report, demonstration,
  slides and viva.

**Critical path:** publish this feature/integration branch only, verify real
read-only isolated Compose normalization, complete bounded runtime verification
of SQLi/XSS/path traversal, resolve M20 independently, then run final
research comparisons and finish academic delivery.

GitHub publication of this integration branch is **not a merge into `main`**.
