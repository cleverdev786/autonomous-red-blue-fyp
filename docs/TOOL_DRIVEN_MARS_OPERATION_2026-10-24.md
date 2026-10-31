# MARS: model-free registered Red/Blue operational mode

**Purpose:** deliver a working local fallback when GGUF inference is slow, mislocalized, malformed or unavailable. This is an additive operational mode, not a replacement for user-selected model experiments or previously archived results.

## How to run

Open the MARS dashboard at `http://127.0.0.1:8090/dashboard/`, select **Remediation**, select one of SQL injection, XSS or path traversal, and choose **Run offline Red → Blue verification**.

The same bounded operation is available to a local operator via:

```bash
python -m services.tool_driven_workflow sql
python -m services.tool_driven_workflow xss
python -m services.tool_driven_workflow traversal
```

The local API endpoint is `POST /api/console/workflows/offline` with JSON `{"scenario":"sql"}`, `{"scenario":"xss"}` or `{"scenario":"traversal"}`. Unregistered names and unexpected fields are rejected. The API runs a fixed Python worker subprocess with a 60-second limit. Only the registered synthetic local application can be tested.

## Real execution stages

1. Check the original local source against its pinned SHA-256. Resolve the registered target and code-defined security test, and validate the metadata/code registry.
2. Create an isolated temporary FastAPI/SQLite/filesystem application; execute the **real existing registered two-step test**. Reject absent exploit evidence or broken normal application behavior.
3. Construct a rule-only Blue analysis bound to the chosen registered scenario. Invoke the **existing** `TrustedRemediationCompiler` with the policy engine, source reader, bounded patch attempts and exact source/AST checks.
4. Reconstruct an isolated patched router **only from the compiler-produced, source-hash-checked template**, then run the same registered test against a separate clean temporary application.
5. Check exploit evidence disappears, normal control behavior is unchanged and health, normal login, rejected-password and search behavior remain functional. Reject the candidate if any criterion fails.
6. Return the machine-readable receipt: actual baseline and patched HTTP statuses, registered test ID, source and patch hashes, normal regression booleans, selected template, and honest provenance.

This stage never calls a model or cloud API, mutates the live repository source, starts a Docker exploit run, commits a Git branch, or deploys a patch. Application `TestClient` executes real HTTP endpoints in-process in the isolated worker; results are **not** Docker replay results. The operator gets a working operational pipeline without pretending this has already shipped production patches.

## Adapting the proposed external-tool architecture

| Source brief capability | Existing MARS capability | This gate / next connection |
|---|---|---|
| Rule-based Red planning | Static target/test registries, policy engine and Red executor | Three allowed registered scenarios selected without an LLM |
| Red verification with HTTP requests | Python registered SQLi/XSS/path-traversal tests | Real baseline and patched FastAPI HTTP replay now wired together |
| Rule-based Blue classification | `services/rule_engine.py` and typed triage | Scenario-bound rule-only Blue path now feeds the trusted compiler |
| Source localization | Source reader, pinned source hash, AST source checks | Source-grounded template localization avoids faulty model line choices |
| Patch generator | `TrustedRemediationCompiler` + `PatchService` | Same exact deterministic patch templates applied to a temporary router |
| Git isolation | Existing GitPython branch orchestration | Reuse existing Git branch services for later deployable patch promotion; not invoked by this endpoint |
| Docker verification | Healthy local isolated Docker services and existing replay helpers | Separate Docker patched-image/live verification is still needed for deployment |
| Semgrep and Bandit | Not installed/verified on the inspected laptop | Add optional structured static-scan adapters after verifying tool versions and suppressions; no remote scanning |
| OWASP ZAP and ModSecurity/CRS | Not installed/verified | Add selectively for defense in depth; do not use crawler/autodiscovery against unknown hosts |
| LibCST | Not installed | Existing exact source-anchor/AST compiler already supports the three registered patterns; only add LibCST if broader codebase transformations become necessary |

## Security and scope

The orchestration must remain restricted to `vulnerable-store` and registered test IDs. A user-supplied path, URL or model-supplied shell command never selects executable work. Failures and unknowns are not called repairs. The worker is subprocess-isolated from the long-running operator service, and source transformation runs only on the exact pinned local teaching source. To support additional app versions, use new reviewed rules and tests instead of turning off source hashing.

## Next practical milestones

- Connect the already-built branch/staging and isolated Docker replayer to this newly verified model-free path. Require separate patched-container health, attack replay, legitimate application checks and rollback before promotion.
- Add a Semgrep structured JSON adapter for general Python source pattern discovery, with allowlisted local source paths and version-pinned rules. Treat scanner output as untrusted observations, not patch authority.
- Add an adaptive orchestrator that selects LLM advice **optionally** when available and otherwise falls back to this deterministic registered-test-and-repair mode.
- Provide a dashboard lifecycle timeline with Red findings, rule/tool evidence, isolated patch candidates, replay results and promotion/rollback states. Preserve historical research archives separately.
