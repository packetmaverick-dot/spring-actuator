# Actuator Scout

A conservative Spring Boot Actuator exposure checker for **your own systems and explicitly authorized assessments**.

## Features

- Checks common current and legacy Actuator paths
- Classifies responses as protected, not found, health, possible Actuator, or potential sensitive exposure
- Optional custom path list, headers, and Basic Auth
- Low concurrency and configurable delay
- JSON and HTML reports; response bodies and secrets are not saved
- Sends **GET requests only**; does not download heap dumps/log files or send write/delete/shutdown requests

## Install

Python 3.10+ recommended.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run against a local lab

```bash
python actuator_scout.py --url http://127.0.0.1:8080/
```

For a context path:

```bash
python actuator_scout.py --url http://127.0.0.1:8080/myapp/ --paths endpoints.txt
```

Scan multiple **authorized** targets:

```bash
python actuator_scout.py --targets targets.txt.example --json results.json --html results.html
```

Optional headers/auth:

```bash
python actuator_scout.py --url https://lab.example/ \
  --header "Authorization: Bearer YOUR_TEST_TOKEN"
python actuator_scout.py --url https://lab.example/ --basic-user testuser --basic-pass 'test-password'
```

Use test credentials only; do not put real secrets in shared reports or shell history. `--insecure` disables TLS validation and should only be used in a controlled lab.

## Output and interpretation

- `PROTECTED`: endpoint returned 401/403.
- `NOT_FOUND`: not found at the tested path.
- `PUBLIC_HEALTH`: health-like JSON is readable; impact depends on returned detail.
- `POTENTIAL_EXPOSURE`: response resembles a sensitive Actuator endpoint.
- `ACTUATOR_INDEX` / `ACTUATOR_RESPONSE` / `POSSIBLE_ACTUATOR`: likely Actuator data requiring manual validation.
- `HTTP_200_REVIEW`: successful response but no strong Actuator signature.

**A status code of 200 is not by itself a vulnerability.** Verify endpoint identity, whether the data is intended to be public, and the security impact. Keep evidence minimal and redact sensitive values.

## Coverage notes

The path list is a starting point, not an exhaustive endpoint database. Endpoint IDs and defaults vary by Spring Boot version, optional dependencies, custom endpoint IDs, `management.endpoints.web.base-path`, `management.server.port`, reverse proxies, and application context paths. If you know a custom base path, supply a tailored `--paths` file. This tool does not scan arbitrary ports or brute-force path names.

It deliberately does not actively request `/actuator/heapdump`, `/actuator/logfile`, state-changing `/actuator/loggers` or `/actuator/env` methods, shutdown, refresh, or DELETE operations. These require explicit manual review in a controlled lab.

## Recommended workflow

1. Confirm written authorization and scope.
2. Run against a known host/base URL, starting with low request volume.
3. Review JSON/HTML results.
4. Manually validate candidate endpoints with a minimal request.
5. Record sanitized status, content type, and a small redacted evidence excerpt.
6. Report actual impact and remediation; do not claim a vulnerability from endpoint reachability alone.

## Defensive remediation

- Expose only required endpoints (prefer allowlisting, e.g. `health`).
- Require authentication and authorization for management endpoints.
- Restrict management interfaces to trusted networks or a separate management port.
- Avoid `include=*` on public interfaces.
- Review Spring Boot's current endpoint security documentation and upgrade affected versions.
