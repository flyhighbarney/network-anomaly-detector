# Security Audit — AI-Powered Network Anomaly Detection System

**Scope:** The Flask dashboard (`src/dashboard/app.py`), the model/artifact
loading path, the CSV upload/prediction flow, and dependency management
(`requirements.txt`).

**Method:** Manual source review of the application as written, mapped to the
2021 OWASP Top 10 and the corresponding CWE identifiers. Every finding below
points at code that actually exists in this repository — none are hypothetical.

**Summary of posture:** The application is a functional ML dashboard built
without security hardening, which is representative of most Flask ML apps. The
highest-impact issues are the Werkzeug debugger being enabled (remote code
execution), an unsanitized upload filename (path traversal / artifact
overwrite), and the complete absence of authentication on the prediction
endpoint.

---

## Summary table

| # | Vulnerability | CWE | OWASP Top 10 | Severity | Status |
|---|---------------|-----|--------------|----------|--------|
| V-01 | Flask/Werkzeug debug mode enabled | CWE-489 | A05:2021 Security Misconfiguration | High | Open |
| V-02 | Hard-coded, weak Flask secret key | CWE-798 | A02:2021 Cryptographic Failures | High | Open |
| V-03 | Path traversal via unsanitized upload filename | CWE-22 | A01:2021 Broken Access Control | High | Open |
| V-04 | Missing authentication on all endpoints | CWE-306 | A07:2021 Identification & Authentication Failures | High | Open |
| V-05 | Insecure deserialization of model files (joblib/pickle) | CWE-502 | A08:2021 Software & Data Integrity Failures | High | Open |
| V-06 | No upload size limit → memory-exhaustion DoS | CWE-400 | A05:2021 Security Misconfiguration | Medium | Open |
| V-07 | Unrestricted upload file type / no content-type check | CWE-434 | A04:2021 Insecure Design | Medium | Open |
| V-08 | Verbose error messages leak internals | CWE-209 | A05:2021 Security Misconfiguration | Medium | Open |
| V-09 | Missing CSRF protection on upload form | CWE-352 | A01:2021 Broken Access Control | Medium | Open |
| V-10 | No rate limiting on prediction endpoint | CWE-770 | A04:2021 Insecure Design | Medium | Open |
| V-11 | Development server bound to all interfaces (0.0.0.0) | CWE-1327 | A05:2021 Security Misconfiguration | Medium | Open |
| V-12 | No integrity verification of model artifacts | CWE-494 | A08:2021 Software & Data Integrity Failures | Medium | Open |
| V-13 | Missing HTTP security headers | CWE-693 | A05:2021 Security Misconfiguration | Low | Open |
| V-14 | Outdated/unpinned transitive dependencies | CWE-1104 | A06:2021 Vulnerable & Outdated Components | Medium | Open |
| V-15 | Insufficient security logging & no audit trail | CWE-778 | A09:2021 Security Logging & Monitoring Failures | Low | Open |

---

## V-01: Flask/Werkzeug debug mode enabled

**CWE**: CWE-489 — Active Debug Code
**OWASP Top 10**: A05:2021 — Security Misconfiguration
**Severity**: High
**Location**: `src/dashboard/app.py:195` — `app.run(host="0.0.0.0", port=5000, debug=True)`

### Description
The app starts with `debug=True`. When an unhandled exception occurs, Werkzeug
renders an interactive traceback that includes a Python console protected only
by a PIN derived from predictable machine attributes. An attacker who can
trigger an exception and reach the debugger can execute arbitrary Python on the
host — a direct remote code execution path. Debug mode also disables template
caching and exposes source snippets.

### Root Cause
Debug mode was left on from local development and hardcoded into `app.run()`
rather than being driven by an environment flag that defaults to off.

### Remediation
Never run with `debug=True` outside a trusted local machine. Drive it from an
environment variable and default to `False`:

```python
import os
app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
```

In production, do not use `app.run()` at all — serve behind a WSGI server
(`gunicorn "src.dashboard.app:app"`).

---

## V-02: Hard-coded, weak Flask secret key

**CWE**: CWE-798 — Use of Hard-coded Credentials
**OWASP Top 10**: A02:2021 — Cryptographic Failures
**Severity**: High
**Location**: `src/dashboard/app.py:31` — `app.secret_key = "dev-secret-key-change-me"`

### Description
The session/flash signing key is a static, publicly known string committed to
source control. Flask uses this key to sign session cookies (and the flash
message store). Anyone who knows the key can forge signed session cookies. Once
authentication is added (V-04), this becomes a full session-forgery /
privilege-escalation primitive.

### Root Cause
A placeholder development key was hardcoded and never externalized.

### Remediation
Load the key from the environment and fail closed if it is absent:

```python
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # 32+ random bytes, never committed
```

Generate with `python -c "import secrets; print(secrets.token_hex(32))"` and
store it in a secret manager / `.env` excluded from version control.

---

## V-03: Path traversal via unsanitized upload filename

**CWE**: CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
**OWASP Top 10**: A01:2021 — Broken Access Control
**Severity**: High
**Location**: `src/dashboard/app.py:155` — `saved_path = UPLOAD_DIR / upload.filename`

### Description
The uploaded file is written to disk using the client-supplied
`upload.filename` verbatim. A crafted filename such as
`../../models/random_forest.joblib` or `../../../etc/whatever` escapes the
uploads directory. An attacker can overwrite the trained model artifacts (which
are then deserialized — see V-05) or clobber arbitrary files the process can
write, leading to model poisoning or code execution on the next load.

### Root Cause
The filename is trusted as a safe path component. `werkzeug.utils.secure_filename`
was not applied, and there is no containment check.

### Remediation
Sanitize the name and verify the resolved path stays inside the upload
directory — or avoid touching disk entirely by reading the stream in memory:

```python
from werkzeug.utils import secure_filename
name = secure_filename(upload.filename) or "upload.csv"
saved_path = (UPLOAD_DIR / name).resolve()
if UPLOAD_DIR.resolve() not in saved_path.parents:
    abort(400)
```

Preferred: `df = pd.read_csv(upload.stream)` — no filesystem write, so there is
no traversal surface and no cleanup (see V-07) required.

---

## V-04: Missing authentication on all endpoints

**CWE**: CWE-306 — Missing Authentication for Critical Function
**OWASP Top 10**: A07:2021 — Identification and Authentication Failures
**Severity**: High
**Location**: `src/dashboard/app.py` — routes `/`, `/predict`, `/insights`, `/chart/<name>` (no `@login_required` or equivalent anywhere)

### Description
Every route, including the file-accepting `/predict` endpoint, is publicly
reachable with no authentication or authorization. Anyone with network access
can upload files, consume compute, and view model internals and metrics.
Combined with V-11 (bound to `0.0.0.0`) this exposes the app to the whole
network.

### Root Cause
No auth layer was designed; the app assumes a trusted single-user local context.

### Remediation
Put the app behind an authentication layer — `Flask-Login` for session auth, an
API key/JWT for programmatic access, or an authenticating reverse proxy (OAuth2
proxy). Restrict `/predict` to authenticated, authorized principals and apply
role checks where appropriate.

---

## V-05: Insecure deserialization of model files (joblib/pickle)

**CWE**: CWE-502 — Deserialization of Untrusted Data
**OWASP Top 10**: A08:2021 — Software and Data Integrity Failures
**Severity**: High
**Location**: `src/dashboard/app.py:52-56` — `joblib.load(...)` for RF, IF, and scaler

### Description
`joblib.load` uses `pickle` under the hood, which executes arbitrary code
embedded in the serialized stream during load. If an attacker can replace a
`.joblib` file (e.g. via the path traversal in V-03, a compromised build
artifact, or a shared filesystem), loading it executes attacker-controlled code
in the server process.

### Root Cause
Trained artifacts are treated as trusted data and loaded without provenance or
integrity guarantees. The traversal bug (V-03) makes the write side reachable.

### Remediation
- Only load artifacts produced by your own trusted pipeline from a
  write-protected location; never load user-supplied model files.
- Verify integrity before loading (see V-12): compare a stored SHA-256 hash /
  signature.
- Consider `skops` (`skops.io`) for safer, allowlist-based (de)serialization of
  scikit-learn models instead of raw pickle/joblib.

---

## V-06: No upload size limit → memory-exhaustion DoS

**CWE**: CWE-400 — Uncontrolled Resource Consumption
**OWASP Top 10**: A05:2021 — Security Misconfiguration
**Severity**: Medium
**Location**: `src/dashboard/app.py` — no `MAX_CONTENT_LENGTH` set; `pd.read_csv(saved_path)` at line 159 loads the whole file

### Description
`app.config["MAX_CONTENT_LENGTH"]` is never set, so uploads are unbounded. The
file is written to disk and then fully materialized into a pandas DataFrame in
memory. A single multi-gigabyte upload can exhaust memory/disk and crash the
worker; repeated uploads amplify the effect. There is also no pagination on the
result table, so a large but valid file renders an enormous HTML response.

### Root Cause
No request-size ceiling and no streaming/row cap on ingestion.

### Remediation
```python
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
```
Additionally cap parsed rows (`pd.read_csv(..., nrows=N)`), paginate the results
table, and set a request timeout at the reverse proxy.

---

## V-07: Unrestricted upload file type / no content-type check

**CWE**: CWE-434 — Unrestricted Upload of File with Dangerous Type
**OWASP Top 10**: A04:2021 — Insecure Design
**Severity**: Medium
**Location**: `src/dashboard/app.py:150-159` — the file is saved and parsed with no server-side type validation (the HTML `accept=".csv"` hint is client-side only and trivially bypassed)

### Description
Any file of any type/extension is accepted and written to `uploads/`. The
`accept=".csv"` attribute in `predict.html` is a client convenience only.
Uploaded files are also never deleted, so the directory grows without bound
(incomplete cleanup, contributing to the DoS in V-06).

### Root Cause
No server-side extension/MIME allowlist and no post-processing cleanup.

### Remediation
Validate the extension against an allowlist server-side, verify the content
parses as CSV before use, and delete the temp file in a `finally` block (or skip
disk entirely per V-03). Store uploads outside any web-served directory.

---

## V-08: Verbose error messages leak internals

**CWE**: CWE-209 — Generation of Error Message Containing Sensitive Information
**OWASP Top 10**: A05:2021 — Security Misconfiguration
**Severity**: Medium
**Location**: `src/dashboard/app.py:165,168` — `flash(f"Missing required columns: {exc}")` and `flash(f"Could not process file: {exc}")`

### Description
Raw exception text is echoed back to the user via flash messages. This can leak
column names, file paths, library versions, and internal logic that aid an
attacker in crafting further input. With debug mode on (V-01) full stack traces
are also exposed.

### Root Cause
Exception objects are formatted directly into user-facing messages.

### Remediation
Show a generic message to the user and log the detail server-side:

```python
except Exception:
    app.logger.exception("prediction failed")
    flash("Could not process the file. Please check the format and try again.")
```

---

## V-09: Missing CSRF protection on upload form

**CWE**: CWE-352 — Cross-Site Request Forgery
**OWASP Top 10**: A01:2021 — Broken Access Control
**Severity**: Medium
**Location**: `src/dashboard/templates/predict.html` (POST form) + `src/dashboard/app.py:predict` (no token validation)

### Description
The multipart POST form carries no anti-CSRF token and the server does not
validate one. Once session-based auth exists (V-04), a malicious page could
force an authenticated victim's browser to submit uploads on their behalf.

### Root Cause
No CSRF middleware is configured.

### Remediation
Add `Flask-WTF` (`CSRFProtect(app)`) and include `{{ csrf_token() }}` in the
form, and/or set `SameSite=Strict` on session cookies.

---

## V-10: No rate limiting on prediction endpoint

**CWE**: CWE-770 — Allocation of Resources Without Limits or Throttling
**OWASP Top 10**: A04:2021 — Insecure Design
**Severity**: Medium
**Location**: `src/dashboard/app.py:predict` — no throttling on any route

### Description
`/predict` performs CPU-intensive work (CSV parsing, scaling, two model
inferences) with no per-client rate limit. An attacker can flood the endpoint to
exhaust CPU/memory and deny service to legitimate users.

### Root Cause
No throttling layer.

### Remediation
Add `Flask-Limiter` (e.g. `@limiter.limit("10/minute")` on `/predict`) backed by
Redis, and/or enforce limits at the reverse proxy.

---

## V-11: Development server bound to all interfaces (0.0.0.0)

**CWE**: CWE-1327 — Binding to an Unrestricted IP Address
**OWASP Top 10**: A05:2021 — Security Misconfiguration
**Severity**: Medium
**Location**: `src/dashboard/app.py:195` — `app.run(host="0.0.0.0", ...)`

### Description
Binding to `0.0.0.0` exposes the Werkzeug development server on every network
interface. The dev server is single-threaded, not hardened for hostile traffic,
and — combined with debug mode (V-01) and no auth (V-04) — publishes an RCE-prone
endpoint to the local network.

### Root Cause
Convenience binding to reach the app from other machines during development.

### Remediation
Bind to `127.0.0.1` for local development. For real deployments run a production
WSGI server (gunicorn/uwsgi) behind a reverse proxy that terminates TLS and
enforces access control.

---

## V-12: No integrity verification of model artifacts

**CWE**: CWE-494 — Download of Code Without Integrity Check
**OWASP Top 10**: A08:2021 — Software and Data Integrity Failures
**Severity**: Medium
**Location**: `src/dashboard/app.py:load_artifacts` (lines 46-58)

### Description
Model, scaler, and metrics files are loaded straight from `models/` with no
checksum or signature check. Given V-03/V-05, a tampered artifact is loaded and
deserialized with no detection, enabling model poisoning or code execution.

### Root Cause
The pipeline assumes artifacts on disk are authentic.

### Remediation
Record a SHA-256 (or signed) manifest at training time and verify each file's
hash before `joblib.load`. Store artifacts in a read-only, access-controlled
location.

---

## V-13: Missing HTTP security headers

**CWE**: CWE-693 — Protection Mechanism Failure
**OWASP Top 10**: A05:2021 — Security Misconfiguration
**Severity**: Low
**Location**: `src/dashboard/app.py` — no `after_request` header hardening

### Description
Responses lack `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options`/frame-ancestors (clickjacking, CWE-1021), and
`Strict-Transport-Security`. This weakens defense-in-depth against XSS, MIME
sniffing, and framing attacks.

### Root Cause
No response-hardening middleware.

### Remediation
Add an `@app.after_request` hook that sets the headers above, or use
`Flask-Talisman` to apply a sensible default policy (including HTTPS
enforcement).

---

## V-14: Outdated / unpinned transitive dependencies

**CWE**: CWE-1104 — Use of Unmaintained Third Party Components
**OWASP Top 10**: A06:2021 — Vulnerable and Outdated Components
**Severity**: Medium
**Location**: `requirements.txt`

### Description
Direct dependencies are pinned with `==`, but transitive dependencies (Werkzeug,
Jinja2, MarkupSafe, etc.) are unpinned, so a fresh install can pull versions with
known CVEs. There is no lockfile and no automated vulnerability scanning. Pinned
direct versions can themselves fall behind published security fixes over time.

### Root Cause
No dependency-locking or vulnerability-scanning process.

### Remediation
Produce a fully resolved lockfile (`pip-compile`/`uv pip compile` →
`requirements.lock` with hashes), install with `--require-hashes`, and run
`pip-audit` / Dependabot in CI to track CVEs. Keep Werkzeug/Flask current.

---

## V-15: Insufficient security logging & no audit trail

**CWE**: CWE-778 — Insufficient Logging
**OWASP Top 10**: A09:2021 — Security Logging and Monitoring Failures
**Severity**: Low
**Location**: `src/dashboard/app.py` — no logging of uploads, predictions, or errors (only `print()` diagnostics in the training pipeline)

### Description
There is no audit trail for who uploaded what, when predictions ran, or when
errors/attacks occurred. Failed parses are shown to the user (V-08) but not
recorded server-side. This blinds incident response and makes abuse detection
impossible.

### Root Cause
No structured application logging was configured.

### Remediation
Configure `app.logger` (or the `logging` module) to record authentication
events, uploads (client, size, sanitized filename), prediction counts, and
errors to a durable, access-controlled sink. Forward to a SIEM and alert on
anomalies (e.g. spikes in failed uploads).

---

## Remediation priority

1. **Immediately (High):** V-01 (debug off), V-03 (sanitize/stream filename),
   V-04 (add auth), V-05 (trusted-only artifact loading), V-02 (externalize
   secret key).
2. **Short term (Medium):** V-06/V-07 (upload limits + type check + cleanup),
   V-08 (generic errors), V-09 (CSRF), V-10 (rate limit), V-11 (bind localhost /
   real WSGI), V-12 (artifact integrity), V-14 (dependency locking + scanning).
3. **Hardening (Low):** V-13 (security headers), V-15 (audit logging).
