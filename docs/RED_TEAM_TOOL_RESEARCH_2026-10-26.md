# Red Team Tool Research and Current Reality (2026-10-26)

Status: **architecture research only**. No tool/image installed, no active scan, no Docker changes or live test executions in this review.

## Observed on the authorized MARS development laptop

- Branch `development` was clean and synchronized with origin at the start of this review.
- Existing orchestration: `orchestrator/red_team_flow.py`, `agents/red/reconnaissance.py`, `agents/red/attack_planner.py`, `agents/red/attack_verifier.py`.
- Trusted surfaces: `services/reconnaissance_service.py`, `services/target_registry.py`, `services/controlled_executor.py`, `orchestrator/policy_engine.py`, typed `schemas/red_team.py`, registry under `config/targets` and `config/security_tests`.
- The existing RedTeamFlow's normal model-assisted path invokes three reasoning roles (recon, planner, verifier), but actual registered HTTP execution is deterministic and policy-controlled, not an LLM. The model-free operational cycle exists separately in `services/tool_driven_workflow.py`.
- Existing lab Compose: one vulnerable-store container plus one controlled-executor, on internal non-attachable bridge `security-lab`. Root filesystem read-only, capabilities dropped, no-new-privileges, unprivileged runtime, CPU/memory/PID caps. Both were healthy during review. The host API listens at `127.0.0.1:8090`.
- Registered target is `vulnerable-store` with three registered tests: `sqli-login-bypass-001`, `xss-reflection-001`, `path-traversal-private-file-001`. The React Red Team page currently contains placeholder copy. `GET /api/console/assessment/registry` is a bounded read-only catalog, not a working Red Team execution API. Existing `services/registered_assessment_plan.py` explicitly sets `execution_enabled: false`.
- Existing Python deps include FastAPI, Pydantic, SQLAlchemy, httpx and GitPython; the lab image uses a Python 3.13 slim base and a hash-pinned dependency lock. No scanner runtimes (ZAP, Nuclei, Semgrep, Bandit) were installed or found among cached Docker image names. The laptop reports approximately 7.6 GiB total RAM, about 4.2 GiB available at inspection. Capacity must be remeasured when adding containers.

## Candidate capabilities and primary source verification

| Option | Packaging verified against first-party sources | Actual MARS fit | Recommendation |
|---|---|---|---|
| Existing `httpx` + fixed registered Python tests | Already in project lock and source | Authorized HTTP recon/controlled execution and known-evidence verification | **Required, reuse; no install** |
| Existing Pydantic + policy engine + registries | Already implemented | Typed plan, scope, budget and evidence checks | **Required, reuse; no install** |
| OWASP ZAP | Official `ghcr.io/zaproxy/zaproxy:stable` or `zaproxy/zap-stable`, Automation Framework in stable image | Scoped HTTP passive observation and optionally OpenAPI-derived API enumeration | **Optional phase 2**, initially passive + strict context only; do not use unrestricted spider/active-scan profiles |
| Semgrep | Official `semgrep/semgrep` container; local CLI also supported | Static source-pattern enrichment for a future multi-file/multi-app target | **Optional phase 2**, read-only checkout and reviewed local rules; scanner results cannot issue executable plans |
| Bandit | PyCQA `pip install bandit`; JSON baseline/report available | Secondary Python source security hints | **Defer** while Semgrep/registered tests already cover the immediate work |
| ProjectDiscovery Nuclei | Official `projectdiscovery/nuclei` container | Template-driven web probes for future approved targets | **Defer**; overlapping registered tests, automatic template updates and unsafe scan breadth need explicit policy, pins and review |
| Nmap / Amass / Subfinder / sqlmap | Not needed for registered synthetic HTTP target; no installation verification attempted | Broad infrastructure/domain recon or general-purpose SQLi testing | **Do not bundle now**. Each requires an independently justified, specifically scoped use case |
| Cloud model APIs / new LLMs | Already optional behind existing provider boundary | Advisory planning/explanation only | **Not required** for executing known tests or binding evidence |

No tool is required to be installed directly on the host. Tool-specific Docker images may be pulled only after review, image digest pinning, security policy and resource budgets. Python-only helpers may be added to the project's locked Python environment where genuinely simpler, not globally to the laptop. Never build a combined privileged scanner image with the operator/UI/model and Docker socket.

### First-party references (verified 2026-10-26)

- ZAP official Docker images and automation: https://www.zaproxy.org/docs/docker/about/ and https://www.zaproxy.org/docs/automate/automation-framework/
- ZAP packaged scan differences: https://www.zaproxy.org/docs/docker/
- Semgrep official Docker image: https://hub.docker.com/r/semgrep/semgrep and local/metrics guidance: https://github.com/semgrep/semgrep
- Nuclei official Docker image: https://hub.docker.com/r/projectdiscovery/nuclei and official documentation on automatic templates / rate controls: https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md
- Bandit project documentation: https://github.com/PyCQA/bandit/blob/main/doc/source/start.rst and PyPI: https://pypi.org/project/bandit/

**Caution:** image *existence* in a registry does not establish local availability or compatibility with the current Docker network. Official floating tags should be replaced by immutable digests at actual adoption time. Some scanners expect network access to update rules; MARS's internal security-lab has no external egress, so ship reviewed, pinned rule files and mount required evidence outputs explicitly.

## Critic: evidence versus convenience

1. **Not four new autonomous executors.** Existing RedTeamFlow has the three typed reasoning roles. The controlled execution stage must stay a trusted service, not an LLM shell or network tool.
2. **Passive scan is not evidence of exploit.** A ZAP alert or Semgrep finding is an *observation*, not a confirmed registered vulnerability. Confirmation needs pinned registered HTTP steps, deterministic evidence checks and a valid source/target/run identity.
3. **Recon cannot silently expand scope.** Registered endpoint metadata remains authoritative; optional scanner-discovered URLs are untrusted candidates that need review and registry admission before a test is executable.
4. **Protect the isolated Compose boundary.** Do not put Docker socket, host network, privileged mode or internet egress in the LLM or executor. A separate tool-runner image joining only the approved lab network is safer than merging scanners into the existing container.
5. **Resources and reproducibility matter.** Multiple image-heavy scanners running together on the inspected 7.6 GiB laptop may exhaust available memory. One optional ephemeral scanner at a time with CPU/RAM/pid/time limits and no surprise background downloads.
6. **Explicitly show unknown and unavailable.** The frontend must distinguish not run, skipped, blocked, timed out, inconclusive, confirmed, and not confirmed. Missing DB/archived evidence must not become a fabricated clean bill of health.
7. **Research claims separate from operational use.** Prior frozen archives stay intact; new developer-facing workflow runs are operational evidence, not automatically final experiment results.
