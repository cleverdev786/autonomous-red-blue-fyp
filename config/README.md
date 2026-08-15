# Human-Controlled Security Registry

This directory contains configuration that defines what the framework is
allowed to test.

## Important

These files are trusted configuration.

LLM agents do not create or modify them.

Generated patches are not allowed to modify them.

## Targets

```text
config/targets/
```

A target definition identifies:

- local container hostname;
- port;
- scheme;
- approved endpoint IDs;
- allowed HTTP methods;
- registered security-test IDs;
- source root;
- writable patch roots;
- log source;
- reset operation;
- request/time limits.

## Security Tests

```text
config/security_tests/
```

Milestone 6 stores only **metadata** for registered tests.

Request/payload templates are implemented in Milestone 7 inside the controlled
security-test harness.

## Authorization Principle

A syntactically valid target, endpoint, method, test ID, or path is not enough.

The deterministic Policy Engine must return `allowed=True` before a sensitive
operation is executed.
