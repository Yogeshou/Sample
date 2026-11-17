# VulnTracker: Security Automation Take-Home (Solution)

Solution to the [Lead Security Automation Engineer assignment](https://github.com/cloudtriquetra/asa-assignment). The original brief is preserved in [`docs/ASSIGNMENT.md`](docs/ASSIGNMENT.md).

| Deliverable | Where |
|---|---|
| Task 1: Shared Report Link feature | `app/main.py` (section *Shared report links*), `app/models.py` (`ShareLink`), tests in `tests/test_api.py` |
| Task 2a: Scan reports | [`reports/`](reports/README.md): baseline + post-remediation |
| Task 2b: Prioritised findings | [`docs/findings.md`](docs/findings.md) |
| Task 3: Remediation and plan | Git history (one commit per fix area) + [`docs/remediation-plan.md`](docs/remediation-plan.md) |
| Task 4: Dockerfile and IaC | [`Dockerfile`](Dockerfile), [`terraform/`](terraform/) |
| Task 5: Executive summary | [`docs/executive-summary.md`](docs/executive-summary.md) |
| CI security gates | [`.github/workflows/ci.yml`](.github/workflows/ci.yml), [`.semgrep/`](.semgrep/), [`.github/dependabot.yml`](.github/dependabot.yml) |

Read the commits in order (`git log --reverse`). The MVP feature commit comes first, then each security fix as its own commit, so the diff for every remediation is easy to review.

---

## Running locally

**Requirements:** Python 3.11, Node.js 20+, Docker.

### Python API (`app/`)

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt          # runtime deps + pytest

# The app fails closed in production mode if no signing key is configured.
export APP_ENV=development                   # enables /docs; ephemeral JWT key if none set
export JWT_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export PUBLIC_BASE_URL=http://localhost:8000 # base for share links (never taken from Host header)

cd app && uvicorn main:app --reload
```

Run tests from the repo root:

```bash
pytest tests/ -v
```

### Notification service (`notify/`)

```bash
cd notify
npm ci
export NOTIFY_API_KEY="$(openssl rand -hex 32)"   # required; the API sends it as a bearer token
export ALLOW_INSECURE_WEBHOOKS=true               # dev only: permit http:// webhook targets
npm start
npm test                                          # stop the service first (same port)
```

To let the API call notify, export the same `NOTIFY_API_KEY` in the API's shell.

### Configuration reference

Any secret can be supplied as `NAME` (env var) or `NAME_FILE` (path to a file, which is how Kubernetes mounts it from the secrets manager).

| Variable | Service | Purpose | Default |
|---|---|---|---|
| `APP_ENV` | API | `production` \| `development` \| `test` | `production` (fails closed) |
| `JWT_SECRET_KEY[_FILE]` | API | HS256 signing key, ≥ 32 chars | **required in production** |
| `DATABASE_URL[_FILE]` | API | SQLAlchemy URL | `sqlite:///./vulntracker.db` |
| `PUBLIC_BASE_URL` | API | Base for generated share links | `http://localhost:8000` |
| `CORS_ALLOWED_ORIGINS` | API | Comma-separated browser origins | empty (CORS off) |
| `NOTIFY_SERVICE_URL` / `NOTIFY_API_KEY[_FILE]` | API | Where and how to call notify | `http://localhost:3001` / none |
| `SHARE_LINK_MAX_FAILED_ATTEMPTS` | API | Bad passwords before a link locks | `10` |
| `NOTIFY_API_KEY[_FILE]` | notify | Bearer key required on all routes except `/health` | **required** |
| `WEBHOOK_SIGNING_SECRET[_FILE]` | notify | HMAC key for `X-VulnTracker-Signature` | falls back to API key |
| `ALLOW_INSECURE_WEBHOOKS` | notify | Allow `http://` targets (dev/test only) | `false` |

---

## Shared Report Link (Task 1)

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/scans/{scan_id}/share` | Bearer | Body `{"password": "optional, 8–128 chars"}` → `201 {"share_url", "expires_at", "password_protected"}`. Only the scan owner can share it. |
| `GET` | `/share/{token}` | Public | Returns a minimised view of the scan. If the link is password-protected, send `X-Share-Password: <pw>` (preferred) or `?password=<pw>` (per spec). |
| `DELETE` | `/scans/{scan_id}/share` | Bearer | Revokes all active links for the scan. *(Added.)* |

**`share_url` decision:** built from the configured `PUBLIC_BASE_URL` (default `http://localhost:8000`), **not** from the request's Host header, because a Host-derived URL can be poisoned to point at an attacker's domain.

**Security properties:** 256-bit CSPRNG token, stored only as SHA-256; fixed 24h server-side expiry; bcrypt-hashed optional password; per-link lockout after 10 failed attempts (HTTP 429); invalid, expired and revoked links all return the same 404; response omits `owner_id` and internal `remediation_notes`; `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`; tokens and query strings redacted from access logs; links are deleted with their scan.

**Assumptions:** "external stakeholder" means read-only access to one scan's core fields. Remediation notes are treated as internal. A link that has locked after too many wrong passwords is replaced by issuing a new one.

---

## Docker (Task 4)

```bash
# Build
docker build -t vulntracker-api:local .

# Run: secrets are injected at runtime, never baked into the image
docker run --rm -p 8000:8000 \
  --read-only --tmpfs /tmp -v vtdata:/app/data \
  --cap-drop ALL --security-opt no-new-privileges \
  -e JWT_SECRET_KEY="$(openssl rand -base64 48)" \
  -e PUBLIC_BASE_URL=http://localhost:8000 \
  vulntracker-api:local

curl http://localhost:8000/health
docker inspect --format '{{.State.Health.Status}}' <container-id>   # → healthy
```

Image properties: `python:3.11.18-slim-trixie` pinned by **digest**; multi-stage build; dependencies installed from a **hash-locked** `requirements.lock` (`--require-hashes`, wheels only); pip/setuptools removed from the runtime layer; runs as UID **10001** with a nologin shell; app code root-owned and read-only; `HEALTHCHECK` on `/health`; exec-form entrypoint; allow-list `.dockerignore`, so no `.git`, tests, `.env` or DB files reach the build context.

`/app/data` holds the SQLite file. The named volume `vtdata` inherits the image's `app`-owned directory, so the read-only container can still write its database.

## Infrastructure (Terraform → AWS EKS)

`terraform/` deploys the API to an existing EKS cluster:

- **Secrets:** AWS Secrets Manager (CMK-encrypted) → **Secrets Store CSI driver** mounts them as tmpfs files. There is no Kubernetes Secret object and nothing in env vars or manifests; the app reads `*_FILE`. Terraform creates only the secret containers, so **values never enter state**. Pod identity is **IRSA**, scoped to `GetSecretValue` on exactly two ARNs, plus `kms:Decrypt` only via Secrets Manager.
- **Network:** namespace-wide **default-deny** ingress and egress. API ingress is allowed only from the ingress-controller namespace on 8000. Egress is limited to cluster DNS and the notify service, which also blocks the cloud metadata endpoint. The Service is `ClusterIP`. Ingress is TLS-only (cert-manager) with rate limits and a 1 MB body cap.
- **Workload hardening:** Pod Security Admission `restricted` enforced on the namespace; `runAsNonRoot`, UID 10001, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token, no service links; CPU, memory and ephemeral-storage requests and limits; liveness and readiness probes; PDB; image must be **digest-pinned** (enforced by variable validation).

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in cluster, OIDC, image digest, hostname
terraform init && terraform plan
# populate secret values out-of-band (never via Terraform):
aws secretsmanager put-secret-value --secret-id "$(terraform output -raw jwt_secret_arn)" \
  --secret-string "$(openssl rand -base64 48)"
```

Cluster prerequisites: Secrets Store CSI driver + AWS provider, a NetworkPolicy-enforcing CNI (VPC CNI network policies / Calico), ingress-nginx, cert-manager, and a `gp3-encrypted` StorageClass.

## CI / security gates

| Job | Tools | Fails the build when |
|---|---|---|
| `test`, `test-notify` | pytest (36 tests), node:test (13 tests) | any test fails |
| `sast` | Semgrep (registry rules + project rules), Bandit | Semgrep ERROR-severity result; Bandit High/High |
| `sca` | pip-audit, npm audit | any known Python vuln; npm High/Critical |
| `container-scan` | docker build + hardened smoke run + Trivy (vuln/secret/misconfig) | image fails to start or become healthy, not UID 10001, or fixable High/Critical CVE |
| `iac-scan` | terraform fmt/validate, Checkov (Terraform + Dockerfile) | any failed check except the documented, time-boxed `CKV2_AWS_57` |

All third-party actions are pinned to commit SHAs; the workflow token is `contents: read`; Dependabot covers pip, npm, Docker, Actions and Terraform. Each job uploads its JSON report as a build artifact named per the brief (`sast.semgrep.json`, `sca.pip-audit.json`, `container.trivy.json`, `iac.checkov.json`).
