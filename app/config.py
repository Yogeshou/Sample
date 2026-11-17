"""Runtime configuration.

All secrets are read from the environment or from files mounted by a secrets
manager (e.g. the Secrets Store CSI driver). Nothing sensitive is hard-coded.

For any setting ``FOO`` the value is resolved in this order:
  1. ``FOO_FILE`` - path to a file whose contents are the value (preferred in
     Kubernetes: secrets never appear in the pod spec or process environment)
  2. ``FOO`` - plain environment variable (convenient for local dev / CI)
  3. a non-secret default, where one is safe
"""
import logging
import os
import secrets
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


def _read(name: str, default: Optional[str] = None) -> Optional[str]:
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)


# "production" is the default so the service fails closed if someone forgets
# to configure it. Use APP_ENV=development (or test) locally.
APP_ENV = os.getenv("APP_ENV", "production").lower()
IS_PRODUCTION = APP_ENV == "production"

DATABASE_URL = _read("DATABASE_URL", "sqlite:///./vulntracker.db")

# --- JWT --------------------------------------------------------------------
ALGORITHM = "HS256"  # fixed server-side; never taken from the token header
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
JWT_ISSUER = "vulntracker-api"

SECRET_KEY = _read("JWT_SECRET_KEY")
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError("JWT_SECRET_KEY (or JWT_SECRET_KEY_FILE) must be set in production")
    # Ephemeral per-process key for dev/test only: tokens die on restart.
    SECRET_KEY = secrets.token_urlsafe(64)
    logger.warning("JWT_SECRET_KEY not set - using an ephemeral key (APP_ENV=%s)", APP_ENV)
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters (256 bits)")

# --- Service-to-service -----------------------------------------------------
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")
NOTIFY_API_KEY = _read("NOTIFY_API_KEY")  # optional; sent as a bearer token to notify

# --- Shared report links ----------------------------------------------------
# Public base URL used to build share links. Deliberately NOT derived from the
# request Host header (Host-header injection -> poisoned links).
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
SHARE_LINK_TTL_HOURS = 24
SHARE_LINK_MAX_FAILED_ATTEMPTS = int(os.getenv("SHARE_LINK_MAX_FAILED_ATTEMPTS", "10"))

# --- CORS -------------------------------------------------------------------
# Comma-separated allow-list of browser origins. Empty = no cross-origin access.
CORS_ALLOWED_ORIGINS: List[str] = [
    o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
]
