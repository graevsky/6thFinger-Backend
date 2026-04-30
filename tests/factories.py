import datetime as dt
import hashlib
import os
import uuid

from app.models.app_settings import AppSettings
from app.models.client_identity import ClientInstance, ClientSession
from app.models.email_code import EmailCode
from app.models.password_reset_session import PasswordResetSession
from app.models.recovery_code import RecoveryCode
from app.models.token import Token
from app.models.user import User
from app.security.hashing import hash_email_code, hash_recovery_code, hash_access_jti


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
    access_token: str = "test-access-jti",
    refresh_token: str = "test-refresh-token",
    expires_at: dt.datetime | None = None,
    revoked: bool = False,
):
    token_hash = hashlib.sha256(refresh_token.encode()).digest()
    row = Token(
        user_id=user_id,
        access_jti_hash=hash_access_jti(access_token),
        token_hash=token_hash,
        expires_at=expires_at or (now_utc() + dt.timedelta(days=7)),
        revoked_at=now_utc() if revoked else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, refresh_token


def create_client_instance(
    db,
    *,
    key_id: str,
    public_key_der: bytes,
    package_name: str = "com.example.a6thfingercontrolapp",
    signing_cert_sha256: str = "B0:91:05:A6:08:50:D7:C9:45:B8:DD:27:BF:0F:C3:37:7F:15:07:2F:AC:AE:EF:32:7F:3A:07:EB:59:F2:F6:8C",
    app_version: str | None = "1.0",
    attestation_security_level: str = "TRUSTED_ENVIRONMENT",
    verified_boot_state: str | None = "VERIFIED",
    device_locked: bool | None = True,
    revoked: bool = False,
):
    row = ClientInstance(
        key_id=key_id,
        public_key_der=public_key_der,
        public_key_sha256=hashlib.sha256(public_key_der).hexdigest(),
        package_name=package_name,
        signing_cert_sha256=signing_cert_sha256,
        app_version=app_version,
        attestation_security_level=attestation_security_level,
        verified_boot_state=verified_boot_state,
        device_locked=device_locked,
        revoked_at=now_utc() if revoked else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_client_session(
    db,
    *,
    client_instance_id,
    session_token: str,
    expires_at: dt.datetime | None = None,
    revoked: bool = False,
):
    row = ClientSession(
        client_instance_id=client_instance_id,
        session_token_hash=hashlib.sha256(session_token.encode()).digest(),
        expires_at=expires_at or (now_utc() + dt.timedelta(minutes=15)),
        revoked_at=now_utc() if revoked else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
