# VulnTracker — Security Findings

**Scope:** `app/` (FastAPI API), `notify/` (Node webhook service), the new *Shared Report Link* feature (Task 1), and the deployment artifacts written for Task 4.
**Method:** automated scans (raw output in `reports/`) and a manual code review. Each tool finding was checked by hand. Severity is my own rating for **this application**, not the CVSS score a tool reports.

## How severity was assessed

VulnTracker stores **a list of the organisation's unpatched weaknesses**. To an attacker that list is a ready-made map of what to attack, so confidentiality of scan data is the main business asset. I rated each finding on three things:

1. **Who can exploit it.** Anyone on the internet, any registered user (registration is open), or an insider with log or repo access.
2. **What they get.** Cross-tenant data, account takeover, internal network access, or nuisance only.
3. **How hard it is.** One request, a chained attack, or something that needs a precondition.

| Rating | Meaning here |
|---|---|
| **Critical** | A single request from an unauthenticated or self-registered attacker exposes every tenant's vulnerability data or takes over accounts |
| **High** | Exposes other tenants' data or credentials, or lets an attacker pivot into the internal network, with modest preconditions |
| **Medium** | Real weakness that needs chaining, insider access, or unusual conditions |
| **Low** | Defence-in-depth or hygiene |

## Tools selected

| Scan | Tool | Why this tool |
|---|---|---|
| SAST | **Semgrep** (public `p/python`, `p/javascript`, `p/owasp-top-ten`, `p/secrets` + project rules in `.semgrep/`) | Covers both Python and JS with one engine. Custom rules turn each bug class found here into a permanent regression guard. Fast enough to block PRs. |
| SAST | **Bandit** | Python-specific second opinion. Cheap to run. |
| SCA | **pip-audit** (PyPA/OSV DB) + **npm audit** (GitHub Advisory DB) | Native resolvers for each ecosystem, so they see the real transitive dependency tree. pip-audit understands hash-locked files. |
| Container | **Trivy** | Scans OS packages, language packages, embedded secrets and Dockerfile misconfiguration in one pass. Free, widely used, can gate on *fixable* High/Critical. Checkov's Dockerfile framework is used as a second check of the image definition. |
| IaC | **Checkov** | The largest free policy set for Terraform, covering both the AWS and Kubernetes resources used here. Supports inline, justified suppressions so exceptions are reviewable. |

---

## Findings (prioritised)

Origin: **S** = starter code, **T1** = my Task 1 feature (found in my own review of the MVP commit `0ac89d9` before hardening), **D** = deployment.

| ID | Finding | Detected by | Severity | Business impact in VulnTracker | Origin | Status |
|---|---|---|---|---|---|---|
| **VT-01** | JWT verification accepts `alg: none` (`algorithms=[ALGORITHM, "none"]`). An unsigned token with any `sub` is accepted. | Semgrep (`jwt-python-none-alg`, custom `jwt-decode-allows-none-algorithm`) | **Critical**: one request, no secret needed, full impersonation | Anyone who knows or guesses a username can act as that user: read, alter, close or delete their findings, and create share links that send the data outside. Authentication is effectively optional. | S | ✅ Fixed |
| **VT-02** | SQL injection in `GET /scans/search`: `q` is pasted into raw SQL via f-string + `text()`. The query is also **not scoped to the caller**. | Semgrep (`avoid-sqlalchemy-text`, custom taint rule), Bandit B608, manual (scoping) | **Critical**: any self-registered user, one request | `UNION SELECT` returns **every tenant's findings** plus the `users` table (emails, bcrypt hashes). Even without injection, a plain search returned other users' scans. This is a data breach of the company's vulnerability backlog. | S | ✅ Fixed |
| **VT-03** | Hard-coded secrets: JWT signing key, DB password, "prod" admin API key (`app/config.py`) and notify service key (`notify/src/config.js`). They are committed to git history. | Semgrep (`p/secrets`, custom), Bandit B105 | **Critical**: anyone with repo read (staff, contractors, a leaked clone, CI logs) can mint valid tokens for any user | Same impact as VT-01, but it survives the VT-01 fix. Because the values are in git history, **removing them from code is not enough; they must be rotated.** | S | ✅ Fixed in code · ⚠️ rotation required |
| **VT-09** | Notify service has **no authentication**. Anyone who can reach it can register a webhook for all events, list every webhook, or POST forged `/notify` events. | Manual, Semgrep (`express-data-exfiltration`, custom) | **High**. Would be Critical if exposed; without a NetworkPolicy every pod in the cluster can reach it. | An attacker subscribes to `scan.created`/`scan.updated` and receives a **live feed of newly found vulnerabilities** across the org. They can also spoof events to downstream systems. | S | ✅ Fixed |
| **VT-10** | Notify: SSRF via webhook URL (any scheme, host or IP, redirects followed). The internal `X-Service-Key` is sent to every registered URL. | Manual, Semgrep (custom `outbound-request-to-user-supplied-url`) | **High**: pivot into the cluster/VPC and to cloud metadata (`169.254.169.254`) for IAM credentials | Cloud credential theft leading to account compromise. Leaking the service key lets attackers impersonate the service. | S | ✅ Fixed (residual: DNS rebinding, see plan) |
| **VT-04** | IDOR on `GET /scans/{id}`: no ownership check. | **Manual only.** No scanner flagged it (authorisation logic is invisible to pattern tools). | **High**: any registered user, IDs are sequential integers | A trivial loop over `/scans/1..N` downloads every tenant's findings. | S | ✅ Fixed |
| **VT-05** | Plain-text passwords written to logs on **every** login attempt, successful or failed. | Semgrep (`python-logger-credential-disclosure`, custom), manual | **High**: needs log access, but logs are widely replicated (SIEM, support, vendors) | Mass credential harvest. Failed attempts often contain passwords for *other* systems (typos, reuse). Breaches retention/privacy obligations. | S | ✅ Fixed |
| **VT-08** | Vulnerable Python dependencies: **67 known vulns in 8 packages**. Notable: python-jose (CVE-2024-33663 algorithm confusion, CVE-2024-33664 JWE DoS), starlette/python-multipart (CVE-2024-47874, CVE-2024-24762 DoS), cryptography 38 (CVE-2023-0286 OpenSSL type confusion), ecdsa (CVE-2024-23342, *no fix available*). | pip-audit | **High**: auth library flaws sit on the authentication path; DoS issues are reachable pre-auth | Weakens auth even after VT-01 is fixed. Pre-auth DoS takes the tracker offline during an incident, which is when it is needed most. | S | ✅ Fixed (upgraded; python-jose/ecdsa/cryptography/multipart/passlib **removed**) |
| **VT-11** | Vulnerable Node dependencies: **11 advisories**. axios 0.21.1 (SSRF/credential leak via absolute URL, CSRF token leak, ReDoS), proxy-addr (Critical, IP spoofing), express/body-parser/path-to-regexp DoS. | npm audit | **High**: axios flaws amplify VT-10; DoS is reachable pre-auth | Notification outage; increases SSRF impact. | S | ✅ Fixed (0 advisories) |
| **VT-T1-3** | Share-link password had **no brute-force protection** on a public, unauthenticated endpoint. | Manual (self-review) | **High**: the password is the *only* control on a password-protected link, and users pick short ones | An attacker holding the link (forwarded email, chat preview, proxy log) guesses until the data is released. | T1 | ✅ Fixed |
| **VT-T1-1** | Share URL built from the request `Host` header (`request.base_url`). | Semgrep (custom `url-built-from-request-host`), manual | **Medium**: needs a proxy/ingress that forwards arbitrary Host values, or a cache-poisoning chain | Customers or auditors receive a link to an attacker's domain. That is phishing under our brand, and the token is captured when they click. | T1 | ✅ Fixed |
| **VT-T1-2** | Share tokens stored in plain text. | Manual (self-review) | **Medium**: needs DB, backup or replica read access, or a chained SQLi such as VT-02 | Anyone who reads the DB can open every live share link without logging in. | T1 | ✅ Fixed |
| **VT-T1-4** | Public share view returned internal fields (`owner_id`, `remediation_notes`). | Manual (self-review) | **Medium**: data minimisation | Internal notes such as patch windows or "accepted risk until Q3" go to a third party. | T1 | ✅ Fixed |
| **VT-T1-5** | Share token (URL path) and password (query string) written to access logs. | Manual (self-review) | **Medium**: insider/log access | Anyone with log access can open the shared reports. | T1 | ✅ Fixed in app logs · ⚠️ ingress/edge logs (see plan) |
| **VT-06** | Global exception handler returns stack trace, exception type and full URL to the client. | Semgrep (custom), manual | **Medium**: information disclosure that helps attackers | Reveals file paths, library versions and SQL fragments, which makes VT-02-style attacks easier. | S | ✅ Fixed |
| **VT-13** | No rate limiting or lockout on `/auth/login`. | Manual | **Medium** | Credential stuffing against accounts, made worse by VT-05 and the lack of MFA. | S | ⏸ Deferred, compensating control in place |
| **VT-14** | Open self-registration: anyone can create an account. | Manual | **Medium**: turns every "any authenticated user" bug into an internet-facing bug | Raised the impact of VT-02 and VT-04 from insider to anyone. | S | ⏸ Deferred (product decision) |
| **VT-16** | SQLite file database: no encryption at rest beyond the volume, no backups, single writer. | Manual | **Medium**: availability and integrity | Data loss or corruption, and no horizontal scaling. | S/D | ⏸ Deferred |
| **VT-21** | Secrets Manager secrets have no automatic rotation. | Checkov `CKV2_AWS_57` | **Medium** | A leaked key stays valid until someone rotates it by hand. | D | ⏸ Deferred, risk accepted for a fixed period |
| **VT-07** | CORS middleware reflects any `Origin` with `Allow-Credentials: true`. | Semgrep (custom), manual | **Low** here. Auth uses a bearer header, not cookies, so browsers don't attach credentials automatically. It would be High with cookie auth. | Becomes exploitable the day someone adds cookie sessions. Cheap to fix now. | S | ✅ Fixed |
| **VT-12** | Notify error handler returns `err.stack`; `metadata` merged with `Object.assign` from user JSON. | Semgrep (custom), manual | **Low** | Information disclosure; prototype-shape tampering of stored objects. | S | ✅ Fixed |
| **VT-19** | Missing input validation: unbounded `limit`, unbounded string sizes, no password policy (`"pw"` accepted). | Manual | **Low** | Resource exhaustion; weak user passwords. | S | ✅ Fixed |
| **VT-15** | No token revocation/logout; HS256 shared-secret JWTs. | Manual | **Low** | A stolen token stays valid for up to 30 minutes. | S | ⏸ Deferred |
| **VT-22** | Username/email enumeration on `/auth/register` ("already registered"). | Manual | **Low** | Makes targeted stuffing easier. (Login timing enumeration *was* fixed with a dummy-hash compare.) | S | ⏸ Deferred |
| **VT-20** | The spec requires the share password as a query parameter, so it can leak via browser history and edge logs. | Manual | **Low** (residual of a requirement) | Mitigated: `X-Share-Password` header supported and preferred, app logs redact query strings. | T1 | ⚠️ Mitigated |

### Triaged scanner results (not findings)

Post-remediation Semgrep reports 7 results (`reports/post-remediation/sast.semgrep.json`). I reviewed each one:

| Rule | Location | Verdict |
|---|---|---|
| `is-function-without-parentheses` | `auth.py`, `main.py` (`user.is_active`) | **False positive**: SQLAlchemy column attribute, not a method. |
| `python-logger-credential-disclosure` | `config.py` ("JWT_SECRET_KEY not set" warning), `main.py` ("Bad share-link password link_id=…") | **False positive**: logs the *name* of the setting or a link id, never a value. |
| `detect-non-literal-fs-filename` | `notify/src/config.js` | **Accepted**: the path is `*_FILE` from operator-controlled deployment config, not request input. Suppressed inline with a justification. |
| `express-check-csurf-middleware-usage` | notify | **N/A**: machine-to-machine API with bearer auth; no cookies, so CSRF does not apply. |
| `unsafe-formatstring` | notify error logger | **False positive**: template literal of a server-generated UUID. |

Checkov `CKV_K8S_14`/`CKV_K8S_43` ("image should use a digest") on the Deployment are **suppressed as false positives**. The image is a variable that a Terraform `validation` block forces to be `repo@sha256:<digest>`, and Checkov cannot resolve variables. Each suppression has its justification inline.

### What the tools missed

The two most exploitable "any registered user" bugs, **VT-04 (IDOR)** and the **missing tenant scoping in search (part of VT-02)**, plus the whole **notify authentication gap (VT-09)** and the share-link brute-force issue (VT-T1-3), were found **only by manual review**. Authorisation and business-logic flaws are not visible to pattern-based scanners. That is why the regression tests in `tests/test_api.py` assert authorisation behaviour directly: one test per finding.
