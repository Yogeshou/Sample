import hashlib
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import List, Literal, Optional

import httpx
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

import models
from auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    password_too_long,
    verify_password,
)
from config import (
    CORS_ALLOWED_ORIGINS,
    IS_PRODUCTION,
    NOTIFY_API_KEY,
    NOTIFY_SERVICE_URL,
    PUBLIC_BASE_URL,
    SHARE_LINK_MAX_FAILED_ATTEMPTS,
    SHARE_LINK_TTL_HOURS,
)
from database import engine, get_db, search_scans_by_query
from models import utcnow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Log hygiene: never write share tokens or query strings (which may carry the
# share-link password) to access logs.
# ---------------------------------------------------------------------------

_SHARE_PATH_RE = re.compile(r"/share/[^/?\s]+")


class _RedactAccessLog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) >= 3 and isinstance(record.args[2], str):
            args = list(record.args)
            path = args[2].split("?", 1)[0]
            args[2] = _SHARE_PATH_RE.sub("/share/[REDACTED]", path)
            record.args = tuple(args)
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactAccessLog())


def _safe_log(value: str, max_len: int = 64) -> str:
    """Strip control characters (log-injection) and truncate user-supplied text."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", value)[:max_len]


models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.1.0",
    # Interactive docs are an information-disclosure aid; only expose outside prod.
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

# SECURITY: explicit allow-list instead of reflecting any Origin with credentials.
if CORS_ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=False,  # API uses bearer tokens, not cookies
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Share-Password"],
        max_age=600,
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if IS_PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # SECURITY: full details go to server logs only; the client gets an opaque
    # correlation id (no stack traces, exception types or internal paths).
    error_id = uuid.uuid4().hex
    logger.exception("Unhandled exception error_id=%s path=%s", error_id, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "error_id": error_id})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

Severity = Literal["critical", "high", "medium", "low"]
ScanStatus = Literal["open", "in_progress", "resolved"]


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(max_length=100, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _bcrypt_limit(cls, v: str) -> str:
        if password_too_long(v):
            raise ValueError("password must be at most 72 bytes")
        return v


class UserLogin(BaseModel):
    username: str = Field(max_length=50)
    password: str = Field(max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    created_at: datetime


class ScanCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10_000)
    severity: Severity = "medium"
    cve_id: Optional[str] = Field(default=None, max_length=30)
    affected_component: str = Field(min_length=1, max_length=200)
    remediation_notes: Optional[str] = Field(default=None, max_length=10_000)


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    remediation_notes: Optional[str] = Field(default=None, max_length=10_000)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime


class ShareCreate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _bcrypt_limit(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and password_too_long(v):
            raise ValueError("password must be at most 72 bytes")
        return v


class ShareOut(BaseModel):
    share_url: str
    expires_at: datetime
    password_protected: bool


class SharedScanOut(BaseModel):
    """External view of a scan. Deliberately omits internal fields
    (owner_id, remediation_notes) - least data necessary for a stakeholder."""

    model_config = ConfigDict(from_attributes=True)

    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    headers = {"Authorization": f"Bearer {NOTIFY_API_KEY}"} if NOTIFY_API_KEY else {}
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            headers=headers,
            timeout=5.0,
        )
    except Exception as exc:  # notification is best-effort
        logger.warning("Notification service unreachable: %s", type(exc).__name__)


def _get_owned_scan(db: Session, scan_id: int, user: models.User) -> models.ScanResult:
    """Fetch a scan only if the caller owns it. 404 (not 403) avoids
    confirming that another tenant's scan id exists."""
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # SECURITY: credentials are never logged.
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    # verify against a dummy hash when the user is unknown -> constant-ish timing
    password_ok = verify_password(payload.password, user.hashed_password if user else None)
    if not user or not password_ok or not user.is_active:
        logger.warning("Failed login for username=%s", _safe_log(payload.username))
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    logger.info("Successful login user_id=%s", user.id)
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}  # nosec B105 - token type label, not a secret


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .order_by(models.ScanResult.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str = Query(..., min_length=2, max_length=100),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    rows = search_scans_by_query(db, q, owner_id=current_user.id)
    results = [ScanOut.model_validate(r).model_dump(mode="json") for r in rows]
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # SECURITY: ownership check (was missing -> IDOR across all tenants)
    return _get_owned_scan(db, scan_id, current_user)


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_owned_scan(db, scan_id, current_user)
    if payload.status is not None:
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_owned_scan(db, scan_id, current_user)
    db.delete(scan)  # share links cascade-delete with the scan
    db.commit()


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------
# Design:
#  * 256-bit random token (secrets.token_urlsafe(32)); only its SHA-256 digest
#    is stored, so a DB leak cannot be replayed as working links.
#  * Expiry is fixed server-side at 24h; the client cannot extend it.
#  * Optional password is bcrypt-hashed; wrong guesses are counted per link and
#    the link locks after SHARE_LINK_MAX_FAILED_ATTEMPTS (brute-force defence
#    that works even if the attacker rotates IPs).
#  * The URL is built from configured PUBLIC_BASE_URL, never the Host header.
#  * Public response is a minimised view (no owner id / internal notes).
#  * Invalid, expired and revoked tokens are indistinguishable (404).

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_NOT_FOUND = HTTPException(status_code=404, detail="Share link not found or expired")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


@app.post("/scans/{scan_id}/share", response_model=ShareOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: Optional[ShareCreate] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = _get_owned_scan(db, scan_id, current_user)
    token = secrets.token_urlsafe(32)  # CSPRNG, 256 bits
    password = payload.password if payload else None
    link = models.ShareLink(
        token_hash=_hash_token(token),
        scan_id=scan.id,
        created_by=current_user.id,
        password_hash=get_password_hash(password) if password else None,
        expires_at=utcnow() + timedelta(hours=SHARE_LINK_TTL_HOURS),
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    logger.info("Share link created link_id=%s scan_id=%s user_id=%s", link.id, scan.id, current_user.id)
    return ShareOut(
        share_url=f"{PUBLIC_BASE_URL}/share/{token}",
        expires_at=link.expires_at,
        password_protected=link.password_hash is not None,
    )


@app.delete("/scans/{scan_id}/share", status_code=204)
def revoke_share_links(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Revoke every active share link for a scan (e.g. link sent to the wrong person)."""
    scan = _get_owned_scan(db, scan_id, current_user)
    count = (
        db.query(models.ShareLink)
        .filter(models.ShareLink.scan_id == scan.id, models.ShareLink.revoked.is_(False))
        .update({models.ShareLink.revoked: True}, synchronize_session=False)
    )
    db.commit()
    logger.info("Revoked %s share link(s) scan_id=%s user_id=%s", count, scan.id, current_user.id)


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    token: str,
    response: Response,
    password: Optional[str] = Query(
        default=None, max_length=128,
        description="Link password. Prefer the X-Share-Password header: query strings leak into logs and history.",
    ),
    x_share_password: Optional[str] = Header(default=None, max_length=128),
    db: Session = Depends(get_db),
):
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    if not _TOKEN_RE.fullmatch(token):
        raise _NOT_FOUND
    link = db.query(models.ShareLink).filter(models.ShareLink.token_hash == _hash_token(token)).first()
    if not link or link.revoked or link.expires_at <= utcnow():
        raise _NOT_FOUND

    if link.password_hash:
        if link.failed_attempts >= SHARE_LINK_MAX_FAILED_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many failed attempts; ask the owner for a new link")
        supplied = x_share_password or password
        if not supplied:
            raise HTTPException(status_code=401, detail="Password required")
        if not verify_password(supplied, link.password_hash):
            link.failed_attempts += 1
            db.commit()
            logger.warning("Bad share-link password link_id=%s attempts=%s", link.id, link.failed_attempts)
            raise HTTPException(status_code=401, detail="Invalid password")

    link.access_count += 1
    link.last_accessed_at = utcnow()
    db.commit()
    logger.info("Share link accessed link_id=%s scan_id=%s", link.id, link.scan_id)
    return link.scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
