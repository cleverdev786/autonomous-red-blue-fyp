# DETERMINISTIC SECURITY-TEST HARNESS

## Purpose

Milestone 7 is the first component allowed to send security-test HTTP requests.

It remains deterministic and restricted.

## Two Registries

### Trusted JSON Metadata

```text
config/security_tests/
```

Defines:

- test ID;
- target ID;
- endpoint ID;
- method;
- allowed parameter names;
- request limit;
- timeout;
- evidence-rule ID.

### Code Implementations

```text
security_tests/
├── registry.py
├── sql_injection/login_bypass.py
├── xss/reflection.py
└── path_traversal/private_file.py
```

The code registry must match the trusted JSON registry exactly.

## Agent Boundary

The controlled executor accepts only:

```text
test_id
attempt_number
```

It does **not** accept:

- raw URL;
- hostname;
- port;
- HTTP method;
- arbitrary header;
- raw payload;
- arbitrary file path;
- shell command.

Destination and request contents are derived from trusted registry/configuration
and fixed code-defined templates.

## Execution Flow

```text
registered test_id
      ↓
trusted metadata lookup
      ↓
code implementation lookup
      ↓
Policy Engine:
  target
  destination
  endpoint
  method
  request budget
      ↓
construct local URL from registry
      ↓
controlled transport
      ↓
structured exchange evidence
      ↓
deterministic evidence rule
      ↓
TestExecutionResult
```

## Registered Tests

### SQL Injection

```text
sqli-login-bypass-001
```

Uses a fixed control request and a fixed local authentication-bypass request.

### XSS

```text
xss-reflection-001
```

Uses a fixed normal query and a fixed synthetic script marker.

### Path Traversal

```text
path-traversal-private-file-001
```

Uses a fixed public-file request and a fixed traversal into the synthetic private
scenario directory.

The dummy app's outer scenario sandbox still prevents host-filesystem escape.

## Redirect Policy

`HttpxTransport` uses:

```text
follow_redirects=False
```

The executor currently blocks all 3xx responses and does not perform a second
request.

This is intentionally stricter than redirect revalidation for the MVP.

## Timeouts

Each registered test metadata file defines its request timeout.

Transport timeout produces a structured `TestExecutionResult` with:

```text
completed = false
timed_out = true
error_code = request-timeout
```

## Evidence

Each exchange records only bounded/sanitized fields:

- exchange ID;
- step ID;
- endpoint ID;
- method;
- status code;
- body excerpt;
- redirect location;
- duration.

The test implementation then evaluates those exchanges using deterministic
evidence rules.

## Docker Runtime Verification

After copying this milestone to the development machine:

```bash
bash scripts/reset_environment.sh
bash scripts/verify_docker_isolation.sh
bash scripts/verify_registered_tests.sh
```

The last script executes all three registered tests **inside the isolated
controlled-executor container**.
