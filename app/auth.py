import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

import models
from config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, JWT_ISSUER, SECRET_KEY
from database import get_db

logger = logging.getLogger(__name__)

security = HTTPBearer()

BCRYPT_MAX_BYTES = 72  # bcrypt ignores (or, in bcrypt>=5, rejects) anything longer

# Pre-computed hash used to equalise timing when the username does not exist,
# so login response time does not reveal which usernames are registered.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equaliser", bcrypt.gensalt()).decode()

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired token",
    headers={"WWW-Authenticate": "Bearer"},
)


def password_too_long(password: str) -> bool:
    return len(password.encode("utf-8")) > BCRYPT_MAX_BYTES


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    if hashed_password is None:
        hashed_password = _DUMMY_HASH
    if password_too_long(plain_password):
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def get_password_hash(password: str) -> str:
    if password_too_long(password):
        raise ValueError("password exceeds 72 bytes")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    to_encode = data.copy()
    to_encode.update({
        "iat": now,
        "exp": now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
        "iss": JWT_ISSUER,
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # SECURITY: the accepted algorithm list is fixed server-side. Never include
    # "none" and never trust the alg in the token header (CVE-class: alg confusion).
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.PyJWTError as exc:
        logger.info("Rejected JWT: %s", type(exc).__name__)
        raise _CREDENTIALS_EXCEPTION


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> models.User:
    payload = decode_token(credentials.credentials)
    username: Optional[str] = payload.get("sub")
    if not username:
        raise _CREDENTIALS_EXCEPTION
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise _CREDENTIALS_EXCEPTION
    return user
