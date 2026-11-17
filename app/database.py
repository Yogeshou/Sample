from sqlalchemy import create_engine, or_
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_scans_by_query(db, query: str, owner_id: int) -> list:
    """Search the caller's own scans by title / description / CVE id.

    SECURITY: uses the ORM so the search term is always a bound parameter
    (fixes SQL injection), and is scoped to ``owner_id`` (fixes cross-tenant
    data exposure - the old raw query returned every user's findings).
    """
    import models  # local import avoids a circular import at module load

    pattern = f"%{_escape_like(query)}%"
    rows = (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == owner_id)
        .filter(
            or_(
                models.ScanResult.title.like(pattern, escape="\\"),
                models.ScanResult.description.like(pattern, escape="\\"),
                models.ScanResult.cve_id.like(pattern, escape="\\"),
            )
        )
        .limit(100)
        .all()
    )
    return rows
