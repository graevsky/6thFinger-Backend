import datetime as dt
import hashlib
import os
import uuid

from app.models.app_settings import AppSettings
from app.models.email_code import EmailCode
from app.models.password_reset_session import PasswordResetSession
from app.models.recovery_code import RecoveryCode
from app.models.token import Token
from app.models.user import User
from app.security.hashing import hash_email_code, hash_recovery_code


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create_user(
    db,
    username: str | None = None,
    email: str | None = None,
    verified: bool = False,
    srp_salt: bytes | None = None,
    srp_verifier: bytes | None = None,
):
    user = User(
        username=(username or f"user_{uuid.uuid4().hex[:8]}").lower(),
        email=email.lower().strip() if email else None,
        email_verified_at=now_utc() if verified and email else None,
        srp_salt=srp_salt or os.urandom(16),
        srp_verifier=srp_verifier or os.urandom(32),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_app_settings(db, user_id, payload: dict | None = None):
    settings = AppSettings(
        user_id=user_id,
        payload=payload or {"language": "en"},
    )
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def create_recovery_code(
    db,
    user_id,
    plain_code: str = "ABCD-EFGH-IJKL",
    used: bool = False,
):
    row = RecoveryCode(
        user_id=user_id,
        code_hash=hash_recovery_code(plain_code),
        used_at=now_utc() if used else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plain_code


def create_email_code(
    db,
    user_id,
    purpose: str,
    target_email: str,
    plain_code: str = "123456",
    expires_at: dt.datetime | None = None,
    attempts: int = 0,
    consumed: bool = False,
):
    row = EmailCode(
        user_id=user_id,
        purpose=purpose,
        target_email=target_email.lower().strip(),
        code_hash=hash_email_code(purpose, plain_code, target_email.lower().strip()),
        expires_at=expires_at or (now_utc() + dt.timedelta(minutes=10)),
        attempts=attempts,
        consumed_at=now_utc() if consumed else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plain_code


def create_password_reset_session(
    db,
    user_id,
    method: str = "email",
    expires_at: dt.datetime | None = None,
    consumed: bool = False,
):
    row = PasswordResetSession(
        user_id=user_id,
        method=method,
        verified_at=now_utc(),
        expires_at=expires_at or (now_utc() + dt.timedelta(minutes=15)),
        consumed_at=now_utc() if consumed else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_token(
    db,
    user_id,
    access_token: str = "test-access-token",
    refresh_token: str = "test-refresh-token",
    expires_at: dt.datetime | None = None,
    revoked: bool = False,
):
    token_hash = hashlib.sha256(refresh_token.encode()).digest()
    row = Token(
        user_id=user_id,
        access_token=access_token.encode(),
        token_hash=token_hash,
        expires_at=expires_at or (now_utc() + dt.timedelta(days=7)),
        revoked_at=now_utc() if revoked else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, refresh_token
