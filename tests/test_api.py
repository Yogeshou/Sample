import base64
import json
import logging
import os
import sys
from datetime import timedelta

import pytest

# Configure the app for tests *before* importing it.
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-key-that-is-at-least-32-chars-long")
os.environ.setdefault("PUBLIC_BASE_URL", "https://vulntracker.example.com")
os.environ.setdefault("NOTIFY_SERVICE_URL", "http://127.0.0.1:9")  # nothing listens; notify is best-effort

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import models  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import _RedactAccessLog, app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)

PW = "password123"


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email=None, password=PW):
    email = email or f"{username}@example.com"
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_scan(token, title="Finding", **extra):
    body = {"title": title, "severity": "high", "affected_component": "api", **extra}
    return client.post("/scans", json=body, headers=auth_headers(token)).json()["id"]


def share(token, scan_id, password=None):
    body = {"password": password} if password else {}
    return client.post(f"/scans/{scan_id}/share", json=body, headers=auth_headers(token))


def token_from(url):
    return url.rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------
# Functional tests (original suite)
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "s3cret-pass",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_rejects_short_password():
    resp = client.post("/auth/register", json={"username": "bob", "email": "bob@example.com", "password": "pw"})
    assert resp.status_code == 422


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "s3cret-pass"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": PW})
    resp = client.post("/auth/login", json={"username": "alice", "password": PW})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": PW})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong-password"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_create_scan_rejects_bad_severity():
    token = register_and_login()
    resp = client.post("/scans", json={"title": "x", "severity": "urgent", "affected_component": "a"},
                       headers=auth_headers(token))
    assert resp.status_code == 422


def test_list_scans():
    token = register_and_login()
    create_scan(token, "Test finding")
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_list_scans_limit_is_capped():
    token = register_and_login()
    assert client.get("/scans?limit=100000", headers=auth_headers(token)).status_code == 422


def test_search_scans():
    token = register_and_login()
    create_scan(token, "SQL Injection via login")
    create_scan(token, "Open redirect")
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["title"] == "SQL Injection via login"


def test_update_scan_status():
    token = register_and_login()
    scan_id = create_scan(token, "Open redirect")
    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = create_scan(token, "Stale finding")
    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Security regression tests (one per remediated finding)
# ---------------------------------------------------------------------------

def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_jwt_alg_none_is_rejected():
    """VT-01: unsigned token must not authenticate."""
    register_and_login()
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'alice', 'exp': 9999999999})}."
    assert client.get("/scans", headers=auth_headers(forged)).status_code == 401


def test_jwt_signed_with_leaked_starter_key_is_rejected():
    """VT-03: the key that was committed to git must no longer be trusted."""
    import jwt
    register_and_login()
    forged = jwt.encode({"sub": "alice", "exp": 9999999999, "iat": 0, "iss": "vulntracker-api"},
                        "v3ry-s3cr3t-jwt-k3y-do-not-share", algorithm="HS256")
    assert client.get("/scans", headers=auth_headers(forged)).status_code == 401


def test_search_sql_injection_payload_is_inert():
    """VT-02: classic UNION/OR payloads are treated as literal text."""
    victim = register_and_login("victim")
    create_scan(victim, "Victim secret finding")
    attacker = register_and_login("attacker")
    for payload in ["' OR '1'='1", "%' UNION SELECT id,username,email,hashed_password,1,1,1,1,1 FROM users--"]:
        resp = client.get("/scans/search", params={"q": payload}, headers=auth_headers(attacker))
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


def test_search_is_scoped_to_owner():
    """VT-02b: search must not return other tenants' findings."""
    victim = register_and_login("victim")
    create_scan(victim, "Victim SQLi finding")
    attacker = register_and_login("attacker")
    assert client.get("/scans/search?q=SQLi", headers=auth_headers(attacker)).json()["count"] == 0


def test_search_like_wildcards_are_literal():
    token = register_and_login()
    create_scan(token, "Anything")
    assert client.get("/scans/search?q=%25%25", headers=auth_headers(token)).json()["count"] == 0


def test_get_scan_idor_blocked():
    """VT-04: another user's scan id returns 404."""
    victim = register_and_login("victim")
    scan_id = create_scan(victim, "Private")
    attacker = register_and_login("attacker")
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(attacker)).status_code == 404


def test_login_does_not_log_password(caplog):
    """VT-05: credentials never reach logs, success or failure."""
    caplog.set_level(logging.DEBUG)
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": PW})
    client.post("/auth/login", json={"username": "alice", "password": PW})
    client.post("/auth/login", json={"username": "alice", "password": "Wr0ng-Secret-Value"})
    assert PW not in caplog.text
    assert "Wr0ng-Secret-Value" not in caplog.text


def test_errors_do_not_leak_stack_traces():
    """VT-06: unhandled errors return an opaque id, not a traceback."""
    @app.get("/__boom")
    def _boom():
        raise RuntimeError("internal detail /etc/secret")

    resp = client.get("/__boom")
    assert resp.status_code == 500
    body = resp.json()
    assert set(body) == {"error", "error_id"}
    assert "Traceback" not in resp.text and "/etc/secret" not in resp.text


def test_cors_does_not_reflect_arbitrary_origin():
    """VT-07: no wildcard/reflected CORS with credentials."""
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") is None
    assert resp.headers.get("access-control-allow-credentials") is None


def test_security_headers_present():
    resp = client.get("/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

def test_share_link_roundtrip():
    token = register_and_login()
    scan_id = create_scan(token, "Shared finding")
    resp = share(token, scan_id)
    assert resp.status_code == 201
    body = resp.json()
    assert body["password_protected"] is False
    resp = client.get(f"/share/{token_from(body['share_url'])}")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Shared finding"


def test_share_link_requires_auth():
    token = register_and_login()
    scan_id = create_scan(token)
    assert client.post(f"/scans/{scan_id}/share", json={}).status_code in (401, 403)


def test_cannot_share_someone_elses_scan():
    victim = register_and_login("victim")
    scan_id = create_scan(victim)
    attacker = register_and_login("attacker")
    assert share(attacker, scan_id).status_code == 404


def test_share_url_ignores_host_header():
    """VT-T1-1: link must use configured base URL, not attacker-controlled Host."""
    token = register_and_login()
    scan_id = create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={},
                       headers={**auth_headers(token), "Host": "evil.example", "X-Forwarded-Host": "evil.example"})
    assert resp.json()["share_url"].startswith("https://vulntracker.example.com/share/")


def test_share_token_not_stored_in_plaintext():
    """VT-T1-2: DB stores only a hash of the token."""
    token = register_and_login()
    scan_id = create_scan(token)
    share_token = token_from(share(token, scan_id).json()["share_url"])
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        assert share_token not in (link.token_hash or "")
        assert len(link.token_hash) == 64
    finally:
        db.close()


def test_share_link_password_query_and_header():
    token = register_and_login()
    scan_id = create_scan(token)
    url = share(token, scan_id, password="correct-horse").json()["share_url"]
    t = token_from(url)
    assert client.get(f"/share/{t}").status_code == 401
    assert client.get(f"/share/{t}", params={"password": "nope-nope"}).status_code == 401
    assert client.get(f"/share/{t}", params={"password": "correct-horse"}).status_code == 200
    assert client.get(f"/share/{t}", headers={"X-Share-Password": "correct-horse"}).status_code == 200


def test_share_link_locks_after_failed_attempts():
    """VT-T1-3: brute force on the link password is bounded."""
    token = register_and_login()
    scan_id = create_scan(token)
    t = token_from(share(token, scan_id, password="correct-horse").json()["share_url"])
    for _ in range(10):
        assert client.get(f"/share/{t}", params={"password": "wrong-guess"}).status_code == 401
    # even the correct password is refused once locked
    assert client.get(f"/share/{t}", params={"password": "correct-horse"}).status_code == 429


def test_share_link_expires_after_24h():
    token = register_and_login()
    scan_id = create_scan(token)
    t = token_from(share(token, scan_id).json()["share_url"])
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        created_window = link.expires_at - link.created_at
        assert timedelta(hours=23, minutes=59) <= created_window <= timedelta(hours=24, minutes=1)
        link.expires_at = models.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    assert client.get(f"/share/{t}").status_code == 404


def test_share_link_revocation():
    token = register_and_login()
    scan_id = create_scan(token)
    t = token_from(share(token, scan_id).json()["share_url"])
    assert client.delete(f"/scans/{scan_id}/share", headers=auth_headers(token)).status_code == 204
    assert client.get(f"/share/{t}").status_code == 404


def test_share_link_deleted_with_scan():
    token = register_and_login()
    scan_id = create_scan(token)
    t = token_from(share(token, scan_id).json()["share_url"])
    client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert client.get(f"/share/{t}").status_code == 404


def test_invalid_tokens_are_indistinguishable():
    assert client.get("/share/not-a-token").status_code == 404
    assert client.get("/share/" + "A" * 43).status_code == 404


def test_shared_view_is_minimised():
    """VT-T1-4: external stakeholders don't see internal fields."""
    token = register_and_login()
    scan_id = create_scan(token, remediation_notes="internal: patch window is Friday")
    t = token_from(share(token, scan_id).json()["share_url"])
    body = client.get(f"/share/{t}").json()
    assert "owner_id" not in body and "remediation_notes" not in body
    assert "X-Robots-Tag" in client.get(f"/share/{t}").headers


def test_access_log_redacts_share_token_and_query():
    """VT-T1-5: tokens and passwords never land in access logs."""
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1,
                            '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4", "GET", "/share/abcDEF123?password=hunter22", "1.1", 200), None)
    _RedactAccessLog().filter(rec)
    msg = rec.getMessage()
    assert "abcDEF123" not in msg and "hunter22" not in msg
    assert "/share/[REDACTED]" in msg
