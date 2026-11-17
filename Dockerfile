# ---------------------------------------------------------------------------
# VulnTracker API - production image
#   * minimal base pinned by tag AND digest (immutable, reproducible)
#   * multi-stage: build tooling never reaches the runtime image
#   * hash-locked dependencies (pip --require-hashes)
#   * non-root (UID 10001), nologin shell, pip/setuptools removed from runtime
#   * no secrets: everything sensitive is injected at runtime
# The base is written literally in each FROM (not via ARG) so Dependabot can
# raise digest-bump PRs and scanners can resolve it.
# ---------------------------------------------------------------------------
# ---- build stage -----------------------------------------------------------
FROM python:3.11.18-slim-trixie@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535 AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps --only-binary=:all: -r requirements.lock \
 && /opt/venv/bin/python -m pip uninstall -y pip setuptools wheel

# ---- runtime stage ---------------------------------------------------------
FROM python:3.11.18-slim-trixie@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535 AS runtime

LABEL org.opencontainers.image.title="vulntracker-api" \
      org.opencontainers.image.description="VulnTracker REST API" \
      org.opencontainers.image.source="https://github.com/<your-username>/<your-repo>" \
      org.opencontainers.image.licenses="Proprietary"

# Pull in Debian security fixes released since the upstream base was built,
# remove the Python package installers from the runtime image (smaller attack
# surface, fewer scanner findings) and create an unprivileged user (fixed UID).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip setuptools wheel \
 && rm -rf /usr/local/bin/pip* /root/.cache \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && mkdir -p /app/data \
 && chown app:app /app/data

COPY --from=build /opt/venv /opt/venv
# Application code is owned by root and read-only for the app user.
COPY --chown=root:root --chmod=0555 app/ /app/

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DATABASE_URL=sqlite:////app/data/vulntracker.db

WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# exec form: uvicorn is PID 1 and receives SIGTERM directly
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
