# Remediation Plan

## 1. What was fixed (and where to see it)

Each fix is its own commit and has at least one regression test that fails on the old code.

| ID | Fix | Commit / file | Regression test |
|---|---|---|---|
| VT-01 | PyJWT; algorithm list fixed server-side to `HS256`; `exp`, `iat`, `sub`, `iss` required | `app/auth.py` | `test_jwt_alg_none_is_rejected` |
| VT-02 | ORM query with bound parameters, LIKE wildcards escaped, results **scoped to caller**, capped at 100 | `app/database.py` | `test_search_sql_injection_payload_is_inert`, `test_search_is_scoped_to_owner`, `test_search_like_wildcards_are_literal` |
| VT-03 | All secrets come from env or `*_FILE` (secrets-manager mount). App **fails closed** in production if missing; minimum 256-bit key enforced. Unused DB password and admin key deleted. | `app/config.py`, `notify/src/config.js` | `test_jwt_signed_with_leaked_starter_key_is_rejected` |
| VT-04 | Shared `_get_owned_scan()` used by every per-scan route; returns 404 (not 403) to avoid confirming the id exists | `app/main.py` | `test_get_scan_idor_blocked`, `test_cannot_share_someone_elses_scan` |
| VT-05 | No credentials in logs; usernames sanitised against log injection; dummy-hash compare removes the user-enumeration timing gap | `app/main.py`, `app/auth.py` | `test_login_does_not_log_password` |
| VT-06 | Opaque 500 with a correlation `error_id`; details stay in server logs | `app/main.py` | `test_errors_do_not_leak_stack_traces` |
| VT-07 | Starlette `CORSMiddleware` with explicit allow-list from config; credentials off | `app/main.py` | `test_cors_does_not_reflect_arbitrary_origin` |
| VT-08 | Upgraded to current releases; **removed** python-jose, ecdsa, passlib, cryptography and python-multipart (none were needed). Runtime and dev dependencies split; Docker installs from a **hash-locked** `requirements.lock`. | `requirements*.txt`, `requirements.lock` | pip-audit: 67 → **0** |
| VT-09 | Bearer-key auth (constant-time compare) on every notify route except `/health`; fails closed if the key is unset | `notify/src/index.js` | `protected routes reject missing or wrong bearer key` |
| VT-10 | Webhook URL policy: https only, no credentials in the URL, private/loopback/link-local/metadata ranges blocked at registration **and** after DNS resolution at send time; redirects disabled; service key no longer sent and replaced by an HMAC-SHA256 body signature | `notify/src/urlPolicy.js`, `dispatcher.js` | `POST /webhooks blocks SSRF targets`, `outbound webhooks are HMAC-signed…` |
| VT-11 | axios 1.x, express 4.22.3; `uuid` dropped (replaced by `crypto.randomUUID`) | `notify/package.json` | npm audit: 11 → **0** |
| VT-12 | Generic error body; metadata copied key-by-key into a sanitised object (no `__proto__`) | `notify/src/index.js` | `errors do not leak stack traces`, prototype test |
| VT-19 | Pydantic constraints: `Literal` enums, length caps, password ≥ 8 chars and ≤ 72 bytes (bcrypt limit), `limit ≤ 100` | `app/main.py` | `test_register_rejects_short_password`, `test_list_scans_limit_is_capped` |
| **Task 1** | VT-T1-1 base URL from config, not Host header · VT-T1-2 SHA-256 token hash at rest · VT-T1-3 per-link lockout after 10 bad passwords (works even if the attacker rotates IPs) · VT-T1-4 minimised public view · VT-T1-5 access-log redaction of `/share/<token>` and query strings · plus revocation endpoint, cascade delete, `noindex`/`no-store` headers | `app/main.py`, `app/models.py` | `test_share_*` (11 tests) |

## 2. What was not fully fixed

| ID | Residual risk | Why not fixed now | Effort to fix | Compensating controls today |
|---|---|---|---|---|
| **VT-03 (rotation)** | The starter JWT key, DB password, admin key and notify key are in **git history** forever. Anyone with a historic clone can still use them against any environment that ever used them. | Rotation is an operational action in each environment, not a code change. Rewriting history (`git filter-repo`) does not remove copies already cloned, so it is optional hygiene, not the control. | **S**: generate new values in Secrets Manager, restart pods; ~1 hour per environment | Code no longer reads those values, and the test proves a token signed with the old key is rejected. **Required action:** rotate before any deployment and add secret scanning (gitleaks/GitHub push protection) to block recurrence. |
| **VT-13** Login brute force | Unlimited password guessing per account at the application layer | Proper lockout needs shared state (Redis) and an anti-lockout-DoS design (progressive delay, CAPTCHA, alerting). The right long-term answer is SSO + MFA, which makes it moot. | **M**: 2–3 days for app-level throttling; SSO integration is a project | Ingress per-IP rate limit (10 rps, 20 connections) in `terraform/kubernetes.tf`; bcrypt cost 12 slows each guess; failed logins logged for SIEM alerting. **Does not stop distributed stuffing.** |
| **VT-14** Open registration | Anyone on the internet can get an account | Product decision: who should be able to sign up? | **S** to disable or invite-only; **M** for SSO | Every data route is now owner-scoped, so a self-registered account sees only its own data. |
| **VT-10 (residual)** DNS rebinding | Attacker DNS can return a public IP at check time and a private one at connect time | A complete fix pins the resolved IP into the socket (custom `lookup`/agent) or routes webhooks through an egress proxy. | **M**: ~1 day + tests | Notify must be deployed with a default-deny egress NetworkPolicy that allows only `0.0.0.0/0 except RFC1918/169.254.0.0/16` on 443. The API's own policy already shows the pattern. Redirects are disabled. |
| **VT-16** SQLite | No PITR backups, single writer (deployment pinned to 1 replica, `Recreate`), data on one encrypted volume | Moving to Postgres (RDS) changes deployment topology; beyond the timebox | **M**: 2–3 days (RDS module, IAM DB auth or secret, Alembic migrations) | Encrypted PVC (`gp3-encrypted`), app reads `DATABASE_URL_FILE` so the switch is configuration-only; PDB. |
| **VT-21** Secret rotation | Manual rotation only (Checkov `CKV2_AWS_57`, soft-fail in CI) | Rotating the HS256 key without logging everyone out requires **multi-key verification** (`kid` header, accept current+previous) | **M**: ~1–2 days (app `kid` support + rotation Lambda) | Short token lifetime (30 min) bounds exposure; CMK with key rotation; access to the secrets limited to one IRSA role. **Time-boxed risk acceptance: 90 days.** |
| **VT-T1-5 / VT-20 (edge logs)** | Ingress/CDN/WAF logs may still record `/share/<token>?password=` | Log config of the shared ingress is owned by the platform team | **S** | App logs redacted; header-based password supported and documented as preferred; links expire in 24h and can be revoked. |
| **VT-15** Token revocation | Stolen access token valid ≤ 30 min | Needs a denylist store or opaque sessions | **M** | Short TTL, TLS-only, `is_active` checked on every request (disabling a user takes effect immediately). |
| **VT-22** Registration enumeration | Can confirm a username/email exists | Low impact; fix comes naturally with invite-only/SSO | **S** | Ingress rate limits. |
| **Share-link scope** | Share is all-or-nothing per scan, shown to anyone who has the link and password; no one-time links, no recipient binding | Out of scope for the prototype | **M** | 24h expiry, revocation endpoint, access counter + `last_accessed_at` for audit, lockout. |
| **Container base OS** | Debian packages in the base image may carry CVEs with no upstream fix | Unfixed upstream; Trivy gates only on **fixable** High/Critical | **S/M**: move to a distroless or Chainguard Python base | Digest-pinned base, Dependabot digest PRs, pip removed from runtime, non-root, read-only root FS, all capabilities dropped, PSA `restricted`. |

## 3. Suggested order of work after this submission

1. **Before any deployment:** rotate all four leaked secrets, populate Secrets Manager, enable GitHub secret scanning + push protection.
2. **Sprint 1:** SSO/OIDC + MFA (closes VT-13, VT-14, VT-22); notify egress NetworkPolicy + IP-pinned dispatch (VT-10 residual).
3. **Sprint 2:** Postgres on RDS + Alembic migrations + backups (VT-16); `kid`-based JWT key rotation + rotation Lambda (VT-21).
4. **Continuous:** keep the CI gates blocking; triage Dependabot PRs weekly; add DAST (OWASP ZAP baseline) against a preview environment.
