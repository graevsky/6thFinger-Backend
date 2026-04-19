import datetime
import hashlib
import secrets
import string
from dataclasses import dataclass
from uuid import UUID
from sqlalchemy.orm import Session
from srptools import SRPContext, SRPServerSession
from srptools.constants import PRIME_2048, PRIME_2048_GEN
import os
from redis.exceptions import RedisError

from app.locale.i18n_email import build_email, normalize_lang
from app.models.app_settings import AppSettings
from app.models.email_code import EmailCode
from app.models.password_reset_session import PasswordResetSession
from app.models.recovery_code import RecoveryCode
from app.models.token import Token
from app.models.user import User
from app.security import srp as srp_utils, tokens
from app.security.hashing import hash_email_code, hash_recovery_code
from app.services.common import ServiceError, now_utc, as_utc
from app.redis_client import get_redis

# SRP public parameters
PRIME = PRIME_2048
GENERATOR = PRIME_2048_GEN

# Email code lifecycle and abuse-protection settings. Should be moved to env or something...
EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_MAX_ATTEMPTS = 5
EMAIL_CODE_RESEND_COOLDOWN_SEC = 60
RESET_SESSION_TTL_MIN = 15

# SRP login state must survive between /login/start and /login/finish,
SRP_SESSION_TTL_SEC = int(os.getenv("SRP_SESSION_TTL_SEC", "300"))
SRP_SESSION_KEY_PREFIX = "auth:srp:session"


@dataclass(frozen=True)
class EmailMessageData:
    """Prepared email payload ready to be passed to the sender."""

    email: str
    subject: str
    text: str


@dataclass(frozen=True)
class LoginStartData:
    """Data returned to the client for the first SRP login step."""

    salt: str
    B: str
    N: str
    g: str


@dataclass(frozen=True)
class LoginFinishData:
    """Data returned after successful SRP proof verification."""

    M2: str
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class PasswordResetStartData:
    """Available recovery methods for the password reset start screen."""

    has_email: bool
    email: str | None
    has_recovery: bool = True


def _err(status: int, code: str, detail: str | None = None) -> None:
    """Raise a normalized service-layer error payload."""
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise ServiceError(status_code=status, detail=payload)


def _normalize_username(username_raw: str) -> str:
    """Lowcase and trim username for storage and comparisons."""
    return username_raw.lower().strip()


def _srp_session_key(username: str) -> str:
    """Redis key for storing SRP session state for a given username."""
    return f"{SRP_SESSION_KEY_PREFIX}:{username}"


def _store_srp_session(username: str, session: SRPServerSession) -> None:
    """Persist SRP session state in Redis with a TTL."""
    try:
        get_redis().set(
            _srp_session_key(username),
            session.private,
            ex=SRP_SESSION_TTL_SEC,
        )
    except RedisError:
        _err(
            503,
            "SRP_SESSION_STORE_UNAVAILABLE",
            "Temporary authentication storage unavailable",
        )


def _get_srp_session_private(username: str) -> str | None:
    """Retrieve SRP session private state from Redis."""
    try:
        return get_redis().get(_srp_session_key(username))
    except RedisError:
        _err(
            503,
            "SRP_SESSION_STORE_UNAVAILABLE",
            "Temporary authentication storage unavailable",
        )


def _delete_srp_session(username: str) -> None:
    """Delete SRP session state from Redis."""
    try:
        get_redis().delete(_srp_session_key(username))
    except RedisError:
        _err(
            503,
            "SRP_SESSION_STORE_UNAVAILABLE",
            "Temporary authentication storage unavailable",
        )


def _restore_srp_session(
    username: str,
    verifier_hex: str,
    session_private: str,
) -> SRPServerSession:
    """Restore SRP server session from Redis state."""
    try:
        ctx = SRPContext(username, "", prime=PRIME, generator=GENERATOR)
        return SRPServerSession(ctx, verifier_hex, private=session_private)
    except Exception:
        _err(
            503,
            "SRP_SESSION_STORE_UNAVAILABLE",
            "Temporary authentication storage unavailable",
        )


def parse_hex_bytes(name: str, hex_str: str) -> bytes:
    """Parse a hex string into bytes."""
    try:
        v = hex_str.strip().lower()
        if len(v) % 2 != 0:
            v = "0" + v
        return bytes.fromhex(v)
    except Exception:
        _err(400, "BAD_HEX", f"{name} must be hex")


def generate_recovery_codes(n: int = 10) -> list[str]:
    """Generate human-readable recovery codes in XXXX-XXXX-XXXX format."""
    alphabet = string.ascii_uppercase + string.digits
    codes: list[str] = []
    for _ in range(n):
        parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
        codes.append("-".join(parts))
    return codes


def generate_email_code() -> str:
    """Generate a 6-digit numeric email code."""
    return "".join(secrets.choice(string.digits) for _ in range(6))


def mask_email(email: str) -> str:
    """Return a masked email for recovery UI."""
    e = (email or "").strip()
    if "@" not in e:
        return "********"
    local, domain = e.split("@", 1)
    if not local:
        return f"********@{domain}"
    first = local[0]
    return f"{first}{'*' * 7}@{domain}"


def get_user_lang(db: Session, user_id) -> str:
    """
    Read user language from app settings.
    English is used as a default.
    """
    s = db.query(AppSettings).filter_by(user_id=user_id).first()
    if not s or not isinstance(s.payload, dict):
        return "en"

    raw = s.payload.get("language") or s.payload.get("lang")
    return normalize_lang(raw, default="en")


def get_srp_params() -> dict[str, str]:
    """Return public SRP constants used by the client."""
    return srp_utils.get_constants()


def register_user(
    db: Session, username_raw: str, salt_hex: str, verifier_hex: str
) -> list[str]:
    """Create a new user and initial recovery codes."""
    username = _normalize_username(username_raw)
    if db.query(User).filter_by(username=username).first():
        _err(409, "USERNAME_TAKEN", "Username already exists")

    salt = parse_hex_bytes("salt", salt_hex)
    verifier = parse_hex_bytes("verifier", verifier_hex)

    user = User(username=username, srp_salt=salt, srp_verifier=verifier)
    db.add(user)
    db.commit()
    db.refresh(user)

    # Recovery codes are generated once on registration and only hashes are stored
    codes_plain = generate_recovery_codes(10)
    rows = [
        RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(c))
        for c in codes_plain
    ]
    db.add_all(rows)
    db.commit()

    return codes_plain


def start_login(db: Session, username_raw: str) -> LoginStartData:
    """Start SRP login by creating a temporary server stored session."""
    username = _normalize_username(username_raw)
    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")

    verifier_hex = user.srp_verifier.hex()
    ctx = SRPContext(username, "", prime=PRIME, generator=GENERATOR)
    server_session = SRPServerSession(ctx, verifier_hex)

    # Save transient SRP state in Redis so login can continue
    _store_srp_session(username, server_session)

    return LoginStartData(
        salt=user.srp_salt.hex(),
        B=server_session.public,
        N=PRIME,
        g=GENERATOR,
    )


def finish_login(
    db: Session,
    username_raw: str,
    A: str,
    M1: str,
    salt: str,
) -> LoginFinishData:
    """Finish SRP login and issue JWT tokens on successful proof verification."""
    username = _normalize_username(username_raw)
    session_private = _get_srp_session_private(username)
    if not session_private:
        _err(400, "NO_ACTIVE_SESSION", "No active session")

    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")

    verifier_hex = user.srp_verifier.hex()
    session = _restore_srp_session(username, verifier_hex, session_private)

    try:
        session.process(A, salt)
        client_M1 = M1.encode("ascii")
        if not session.verify_proof(client_M1):
            raise ValueError("Proof mismatch")
    except Exception:
        _err(401, "WRONG_PASSWORD", "Invalid username or password")

    access_token, access_jti_hash = tokens.create_access_token({"sub": str(user.id)})
    refresh_token, refresh_hash, expire = tokens.create_refresh_token(
        {"sub": str(user.id)}
    )

    # Refresh token is tracked by hash, access stored directly. Not very good, but ok...kinda
    db.add(
        Token(
            user_id=user.id,
            access_jti_hash=access_jti_hash,
            token_hash=refresh_hash,
            expires_at=expire,
            last_used_at=now_utc(),
        )
    )
    db.commit()

    # Delete the SRP session only after successful login finalization.
    _delete_srp_session(username)

    return LoginFinishData(
        M2=session.key_proof_hash.decode("ascii"),
        access_token=access_token,
        refresh_token=refresh_token,
    )


def refresh_access_token(db: Session, refresh_token_raw: str | None) -> dict[str, str]:
    """Issue a new access token from a valid non-revoked refresh token."""
    token_str = refresh_token_raw
    if not token_str:
        _err(400, "MISSING_TOKEN", "Missing token")

    payload = tokens.verify_token(token_str)
    if not payload or payload.get("typ") != "refresh":
        _err(401, "INVALID_REFRESH", "Invalid refresh token")

    token_hash = hashlib.sha256(token_str.encode()).digest()
    db_token = db.query(Token).filter_by(token_hash=token_hash, revoked_at=None).first()
    if not db_token:
        _err(401, "TOKEN_REVOKED", "Token revoked or missing")

    new_access, new_access_jti_hash = tokens.create_access_token({"sub": payload["sub"]})
    db_token.access_jti_hash = new_access_jti_hash
    db_token.last_used_at = now_utc()
    db.commit()

    return {"access_token": new_access}


def logout_user(db: Session, user_id: UUID) -> None:
    """Logout user -> revoke all active token rows for the user."""
    db.query(Token).filter_by(user_id=user_id, revoked_at=None).update(
        {
            "revoked_at": now_utc(),
            "last_used_at": now_utc(),
        }
    )
    db.commit()


def get_me_data(user: User) -> dict[str, str]:
    """Return a user representation."""
    return {"id": str(user.id), "username": user.username}


def _normalize_email(email: str) -> str:
    """Lowcase email is stored."""
    return email.lower().strip()


def _get_user_by_id_or_404(db: Session, user_id) -> User:
    """Load user by its id"""
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")
    return user


def _get_user_by_username_or_404(db: Session, username_raw: str) -> User:
    """Load user by username."""
    username = username_raw.lower().strip()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")
    return user


def _ensure_email_not_in_use(db: Session, email: str, current_user_id) -> None:
    """Ensure email is not already attached to another user."""
    other = (
        db.query(User).filter(User.email == email, User.id != current_user_id).first()
    )
    if other:
        _err(409, "EMAIL_IN_USE", "Email already in use")


def _ensure_no_recent_code(db: Session, user_id, purpose: str, email: str) -> None:
    """
    Enforce resend cooldown for email codes.
    This cooldown is checked per user + purpose + target email.
    """
    cutoff = now_utc() - datetime.timedelta(seconds=EMAIL_CODE_RESEND_COOLDOWN_SEC)
    recent = (
        db.query(EmailCode)
        .filter_by(user_id=user_id, purpose=purpose, target_email=email)
        .filter(EmailCode.created_at >= cutoff)
        .first()
    )
    if recent:
        _err(429, "TOO_MANY_REQUESTS", "Too many requests. Try later.")


def _consume_pending_codes(db: Session, user_id, purpose: str, email: str) -> None:
    """Invalidate older unconsumed codes before issuing a new one."""
    db.query(EmailCode).filter_by(
        user_id=user_id,
        purpose=purpose,
        target_email=email,
        consumed_at=None,
    ).update({"consumed_at": now_utc()})


def _create_email_code(db: Session, user_id, purpose: str, email: str) -> str:
    """Create and persist a new email code."""
    code_plain = generate_email_code()
    expires = now_utc() + datetime.timedelta(minutes=EMAIL_CODE_TTL_MIN)

    row = EmailCode(
        user_id=user_id,
        purpose=purpose,
        target_email=email,
        code_hash=hash_email_code(purpose, code_plain, email),
        expires_at=expires,
        attempts=0,
    )
    db.add(row)
    db.commit()
    return code_plain


def _build_email_message(
    db: Session, user_id, purpose: str, email: str, code_plain: str
) -> EmailMessageData:
    """Build localized email subject and text for the given purpose."""
    lang = get_user_lang(db, user_id)
    subject, text = build_email(lang, purpose, code_plain, EMAIL_CODE_TTL_MIN)
    return EmailMessageData(
        email=email,
        subject=subject,
        text=text,
    )


def _get_latest_pending_email_code(
    db: Session, user_id, purpose: str, email: str
) -> EmailCode:
    """Return the latest unconsumed code row for verification."""
    row = (
        db.query(EmailCode)
        .filter_by(
            user_id=user_id, purpose=purpose, target_email=email, consumed_at=None
        )
        .order_by(EmailCode.created_at.desc())
        .first()
    )
    if not row:
        _err(400, "NO_PENDING_CODE", "No pending code")
    return row


def _verify_email_code_or_fail(
    db: Session,
    row: EmailCode,
    purpose: str,
    email: str,
    code: str,
) -> None:
    """
    Validate an email code row and mark it consumed on success.
    Wrong code increments attempts immediately. Not used much though
    Successful verification also increments attempts and destroys the row.
    """
    if as_utc(row.expires_at) < now_utc():
        _err(400, "CODE_EXPIRED", "Code expired")

    if row.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        _err(429, "TOO_MANY_ATTEMPTS", "Too many attempts")

    expected = hash_email_code(purpose, code, email)
    if row.code_hash != expected:
        row.attempts += 1
        db.commit()
        _err(400, "WRONG_CODE", "Wrong code")

    row.consumed_at = now_utc()
    row.attempts += 1


def _has_unused_recovery_codes(db: Session, user_id) -> bool:
    """True if at least one recovery code is still available."""
    return (
        db.query(RecoveryCode.id).filter_by(user_id=user_id, used_at=None).first()
        is not None
    )


def prepare_email_add(db: Session, user_id, email_raw: str) -> str:
    """Validate email add request before sending a code."""
    email = _normalize_email(email_raw)

    _ensure_email_not_in_use(db, email, user_id)
    _ensure_no_recent_code(db, user_id, "email_add", email)

    return email


def prepare_email_remove(db: Session, user_id) -> str:
    """Validate email remove request and return current verified email."""
    user = _get_user_by_id_or_404(db, user_id)
    if not user.email or not user.email_verified_at:
        _err(400, "NO_VERIFIED_EMAIL", "No verified email")

    email = _normalize_email(user.email)
    _ensure_no_recent_code(db, user.id, "email_remove", email)

    return email


def prepare_password_reset_email_send(
    db: Session,
    username_raw: str,
    email_raw: str,
) -> tuple[User, str]:
    """Validate password reset by email before creating a code."""
    user = _get_user_by_username_or_404(db, username_raw)
    email = _normalize_email(email_raw)

    if not user.email or not user.email_verified_at:
        _err(400, "EMAIL_NOT_SET", "Email not set")

    if _normalize_email(user.email) != email:
        _err(400, "EMAIL_MISMATCH", "Email mismatch")

    _ensure_no_recent_code(db, user.id, "password_reset", email)

    return user, email


def issue_email_code_message(
    db: Session,
    user_id,
    purpose: str,
    email: str,
) -> EmailMessageData:
    """Invalidate previous codes, create a fresh one, and build the email message."""
    _consume_pending_codes(db, user_id, purpose, email)
    code_plain = _create_email_code(db, user_id, purpose, email)
    return _build_email_message(db, user_id, purpose, email, code_plain)


def start_add_email(db: Session, user_id, email_raw: str) -> EmailMessageData:
    """Combined helper for email-add."""
    email = prepare_email_add(db, user_id, email_raw)
    return issue_email_code_message(db, user_id, "email_add", email)


def confirm_add_email(db: Session, user_id, email_raw: str, code_raw: str) -> None:
    """Verify email-add code and attach the email to the user."""
    email = _normalize_email(email_raw)
    code = code_raw.strip()

    row = _get_latest_pending_email_code(db, user_id, "email_add", email)
    _verify_email_code_or_fail(db, row, "email_add", email, code)

    # Re-check uniqueness here because another user may have claimed the email before it was confirmed
    _ensure_email_not_in_use(db, email, user_id)

    user = _get_user_by_id_or_404(db, user_id)
    user.email = email
    user.email_verified_at = now_utc()

    db.commit()


def start_remove_email(db: Session, user_id) -> EmailMessageData:
    """Combined helper for email-remove flow."""
    email = prepare_email_remove(db, user_id)
    return issue_email_code_message(db, user_id, "email_remove", email)


def confirm_remove_email(
    db: Session,
    user_id,
    code_raw: str | None = None,
    recovery_code_raw: str | None = None,
) -> None:
    """Remove verified email using either email code or recovery code."""
    user = _get_user_by_id_or_404(db, user_id)
    if not user.email or not user.email_verified_at:
        _err(400, "NO_VERIFIED_EMAIL", "No verified email")

    email = _normalize_email(user.email)

    if code_raw:
        code = code_raw.strip()
        row = _get_latest_pending_email_code(db, user.id, "email_remove", email)
        _verify_email_code_or_fail(db, row, "email_remove", email, code)

        user.email = None
        user.email_verified_at = None
        db.commit()
        return

    if recovery_code_raw:
        rc = recovery_code_raw.strip().upper()
        digest = hash_recovery_code(rc)
        rec = (
            db.query(RecoveryCode)
            .filter_by(user_id=user.id, code_hash=digest, used_at=None)
            .first()
        )
        if not rec:
            _err(400, "WRONG_RECOVERY_CODE", "Wrong recovery code")

        rec.used_at = now_utc()
        user.email = None
        user.email_verified_at = None
        db.commit()
        return

    _err(400, "MISSING_CODE", "Provide code or recovery_code")


def password_reset_start(db: Session, username_raw: str) -> PasswordResetStartData:
    """Return which password reset methods are currently available."""
    user = _get_user_by_username_or_404(db, username_raw)

    has_email = bool(user.email and user.email_verified_at)
    masked = mask_email(user.email) if has_email and user.email else None
    has_recovery = _has_unused_recovery_codes(db, user.id)

    return PasswordResetStartData(
        has_email=has_email,
        email=masked,
        has_recovery=has_recovery,
    )


def password_reset_email_send(
    db: Session,
    username_raw: str,
    email_raw: str,
) -> EmailMessageData:
    """Combined helper for password reset email-code issuing."""
    user, email = prepare_password_reset_email_send(db, username_raw, email_raw)
    return issue_email_code_message(db, user.id, "password_reset", email)


def password_reset_email_verify(
    db: Session,
    username_raw: str,
    email_raw: str,
    code_raw: str,
):
    """Verify password reset email code and create a short-lived reset session."""
    user = _get_user_by_username_or_404(db, username_raw)
    email = _normalize_email(email_raw)
    code = code_raw.strip()

    if not user.email or not user.email_verified_at:
        _err(400, "EMAIL_NOT_SET", "Email not set")

    if _normalize_email(user.email) != email:
        _err(400, "EMAIL_MISMATCH", "Email mismatch")

    row = _get_latest_pending_email_code(db, user.id, "password_reset", email)
    _verify_email_code_or_fail(db, row, "password_reset", email, code)

    sess = PasswordResetSession(
        user_id=user.id,
        method="email",
        verified_at=now_utc(),
        expires_at=now_utc() + datetime.timedelta(minutes=RESET_SESSION_TTL_MIN),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    return sess.id


def password_reset_recovery_verify(
    db: Session, username_raw: str, recovery_code_raw: str
):
    """Verify recovery code and create a short-lived password reset session."""
    user = _get_user_by_username_or_404(db, username_raw)
    code_plain = recovery_code_raw.strip().upper()

    digest = hash_recovery_code(code_plain)
    rec = (
        db.query(RecoveryCode)
        .filter_by(user_id=user.id, code_hash=digest, used_at=None)
        .first()
    )
    if not rec:
        _err(400, "WRONG_RECOVERY_CODE", "Wrong recovery code")

    # Recovery code is single-use
    rec.used_at = now_utc()

    sess = PasswordResetSession(
        user_id=user.id,
        method="recovery_code",
        verified_at=now_utc(),
        expires_at=now_utc() + datetime.timedelta(minutes=RESET_SESSION_TTL_MIN),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    return sess.id


def password_reset_finish(
    db: Session,
    reset_session_id,
    new_salt_hex: str,
    new_verifier_hex: str,
) -> None:
    """Finalize password reset by rotating stored SRP credentials."""
    sess = db.query(PasswordResetSession).filter_by(id=reset_session_id).first()
    if not sess:
        _err(400, "INVALID_SESSION", "Invalid session")

    if sess.consumed_at is not None:
        _err(400, "SESSION_ALREADY_USED", "Session already used")

    if as_utc(sess.expires_at) < now_utc():
        _err(400, "SESSION_EXPIRED", "Session expired")

    user = db.query(User).filter_by(id=sess.user_id).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")

    new_salt = parse_hex_bytes("new_salt", new_salt_hex)
    new_verifier = parse_hex_bytes("new_verifier", new_verifier_hex)

    user.srp_salt = new_salt
    user.srp_verifier = new_verifier

    db.query(Token).filter_by(user_id=user.id, revoked_at=None).update(
        {
            "revoked_at": now_utc(),
            "last_used_at": now_utc(),
        }
    )

    sess.consumed_at = now_utc()
    db.commit()
