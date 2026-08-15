# TARGET REGISTRY AND POLICY ENGINE

## Purpose

Milestone 6 introduces the deterministic authorization layer that sits between
agent recommendations and privileged project actions.

An agent recommendation is never authorization.

## Trusted Registry

Human-controlled configuration:

```text
config/
├── targets/
│   └── vulnerable-store.json
└── security_tests/
    ├── sqli-login-bypass-001.json
    ├── xss-reflection-001.json
    └── path-traversal-private-file-001.json
```

The files contain metadata only. Security-test request templates are implemented
later in the controlled executor.

## Policy Checks

`orchestrator/policy_engine.py` validates:

- registered target;
- exact registered scheme;
- exact registered hostname;
- exact registered port;
- endpoint ID;
- HTTP method;
- security-test ID;
- security-test target/endpoint consistency;
- source-read root;
- protected secret files;
- patch writable root;
- protected framework/test/config paths;
- workflow state transition;
- model-call budget;
- attack-attempt budget;
- patch-attempt budget;
- HTTP-request budget;
- total run time.

## Fail-Closed Rule

Unknown or mismatched values are rejected.

Examples:

```text
example.com                     → BLOCK
127.0.0.1 as attack target      → BLOCK
port 22                         → BLOCK
unregistered endpoint           → BLOCK
unregistered test ID            → BLOCK
../ path escape                 → BLOCK
/etc/passwd                     → BLOCK
orchestrator/policy_engine.py   → BLOCK for generated patch
baseline tests                  → BLOCK for generated patch
```

## Writable Patch Roots

Current target configuration permits generated patch proposals only under:

```text
dummy_apps/vulnerable_store/app/
dummy_apps/vulnerable_store/tests/generated/
```

This allows remediation of the deliberately vulnerable app while keeping:

- orchestrator;
- policy engine;
- registry configuration;
- Docker configuration;
- dependency configuration;
- mandatory baseline tests

outside the generated-patch boundary.

## Workflow

The policy layer also validates the explicit workflow state graph.

An invalid jump such as:

```text
CREATED → PATCH_APPLYING
```

is rejected.

Safety/error transitions to:

```text
FAILED
POLICY_BLOCKED
```

are allowed from active states.

## Run Limits

`orchestrator/limits.py` owns measurable counters and time:

- model calls;
- attack attempts;
- patch attempts;
- HTTP requests;
- elapsed runtime.

The policy engine checks budget availability before later privileged services
consume those resources.

## Important Boundary

Milestone 6 still performs **no security-test HTTP execution**.

That begins only in Milestone 7, where the controlled executor must ask this
policy layer for approval before sending registered local requests.
