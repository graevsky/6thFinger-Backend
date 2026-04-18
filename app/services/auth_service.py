import datetime
import hashlib
import secrets
import string
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.orm import Session
from srptools import SRPContext, SRPServerSession
from srptools.constants import PRIME_2048, PRIME_2048_GEN

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


PRIME = PRIME_2048
GENERATOR = PRIME_2048_GEN

EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_MAX_ATTEMPTS = 5
EMAIL_CODE_RESEND_COOLDOWN_SEC = 60

RESET_SESSION_TTL_MIN = 15

active_sessions: dict[str, SRPServerSession] = {}


@dataclass(frozen=True)
class EmailMessageData:
    email: str
    subject: str
    text: str


@dataclass(frozen=True)
class LoginStartData:
    salt: str
    B: str
    N: str
    g: str


@dataclass(frozen=True)
class LoginFinishData:
    M2: str
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class PasswordResetStartData:
    has_email: bool
    email: str | None
    has_recovery: bool = True


def _err(status: int, code: str, detail: str | None = None) -> None:
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise ServiceError(status_code=status, detail=payload)


def parse_hex_bytes(name: str, hex_str: str) -> bytes:
    try:
        v = hex_str.strip().lower()
        if len(v) % 2 != 0:
            v = "0" + v
        return bytes.fromhex(v)
    except Exception:
        _err(400, "BAD_HEX", f"{name} must be hex")


def generate_recovery_codes(n: int = 10) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    codes: list[str] = []
    for _ in range(n):
        parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
        codes.append("-".join(parts))
    return codes


def generate_email_code() -> str:
    return "".join(secrets.choice(string.digits) for _ in range(6))


def mask_email(email: str) -> str:
    e = (email or "").strip()
    if "@" not in e:
        return "********"
    local, domain = e.split("@", 1)
    if not local:
        return f"********@{domain}"
    first = local[0]
    return f"{first}{'*' * 7}@{domain}"


def get_user_lang(db: Session, user_id) -> str:
    s = db.query(AppSettings).filter_by(user_id=user_id).first()
    if not s or not isinstance(s.payload, dict):
        return "en"

    raw = s.payload.get("language") or s.payload.get("lang")
    return normalize_lang(raw, default="en")


def get_srp_params() -> dict[str, str]:
    return srp_utils.get_constants()


def register_user(
    db: Session, username_raw: str, salt_hex: str, verifier_hex: str
) -> list[str]:
    username = username_raw.lower().strip()
    if db.query(User).filter_by(username=username).first():
        _err(409, "USERNAME_TAKEN", "Username already exists")

    salt = parse_hex_bytes("salt", salt_hex)
    verifier = parse_hex_bytes("verifier", verifier_hex)

    user = User(username=username, srp_salt=salt, srp_verifier=verifier)
    db.add(user)
    db.commit()
    db.refresh(user)

    codes_plain = generate_recovery_codes(10)
    rows = [
        RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(c))
        for c in codes_plain
    ]
    db.add_all(rows)
    db.commit()

    return codes_plain


def start_login(db: Session, username_raw: str) -> LoginStartData:
    username = username_raw.lower().strip()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")

    verifier_hex = user.srp_verifier.hex()
    ctx = SRPContext(username, "", prime=PRIME, generator=GENERATOR)
    server_session = SRPServerSession(ctx, verifier_hex)
    active_sessions[username] = server_session

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
    username = username_raw.lower().strip()
    session = active_sessions.get(username)
    if not session:
        _err(400, "NO_ACTIVE_SESSION", "No active session")

    try:
        session.process(A, salt)
        client_M1 = M1.encode("ascii")
        if not session.verify_proof(client_M1):
            raise ValueError("Proof mismatch")
    except Exception:
        _err(401, "WRONG_PASSWORD", "Invalid username or password")

    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")

    access_token = tokens.create_access_token({"sub": str(user.id)})
    refresh_token, refresh_hash, expire = tokens.create_refresh_token(
        {"sub": str(user.id)}
    )

    db.add(
        Token(
            user_id=user.id,
            access_token=access_token.encode(),
            token_hash=refresh_hash,
            expires_at=expire,
            last_used_at=now_utc(),
        )
    )
    db.commit()
    active_sessions.pop(username, None)

    return LoginFinishData(
        M2=session.key_proof_hash.decode("ascii"),
        access_token=access_token,
        refresh_token=refresh_token,
    )


def refresh_access_token(db: Session, refresh_token_raw: str | None) -> dict[str, str]:
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

    new_access = tokens.create_access_token({"sub": payload["sub"]})
    db_token.access_token = new_access.encode()
    db_token.last_used_at = now_utc()
    db.commit()

    return {"access_token": new_access}


def logout_user(db: Session, user_id: UUID) -> None:
    db.query(Token).filter_by(user_id=user_id, revoked_at=None).update(
        {
            "revoked_at": now_utc(),
            "last_used_at": now_utc(),
        }
    )
    db.commit()


def get_me_data(user: User) -> dict[str, str]:
    return {"id": str(user.id), "username": user.username}


def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _get_user_by_id_or_404(db: Session, user_id) -> User:
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")
    return user


def _get_user_by_username_or_404(db: Session, username_raw: str) -> User:
    username = username_raw.lower().strip()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        _err(404, "USER_NOT_FOUND", "User not found")
    return user


def _ensure_email_not_in_use(db: Session, email: str, current_user_id) -> None:
    other = (
        db.query(User).filter(User.email == email, User.id != current_user_id).first()
    )
    if other:
        _err(409, "EMAIL_IN_USE", "Email already in use")


def _ensure_no_recent_code(db: Session, user_id, purpose: str, email: str) -> None:
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
    db.query(EmailCode).filter_by(
        user_id=user_id,
        purpose=purpose,
        target_email=email,
        consumed_at=None,
    ).update({"consumed_at": now_utc()})


def _create_email_code(db: Session, user_id, purpose: str, email: str) -> str:
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
    return (
        db.query(RecoveryCode.id).filter_by(user_id=user_id, used_at=None).first()
        is not None
    )


def prepare_email_add(db: Session, user_id, email_raw: str) -> str:
    email = _normalize_email(email_raw)

    _ensure_email_not_in_use(db, email, user_id)
    _ensure_no_recent_code(db, user_id, "email_add", email)

    return email


def prepare_email_remove(db: Session, user_id) -> str:
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
    _consume_pending_codes(db, user_id, purpose, email)
    code_plain = _create_email_code(db, user_id, purpose, email)
    return _build_email_message(db, user_id, purpose, email, code_plain)


def start_add_email(db: Session, user_id, email_raw: str) -> EmailMessageData:
    email = prepare_email_add(db, user_id, email_raw)
    return issue_email_code_message(db, user_id, "email_add", email)


def confirm_add_email(db: Session, user_id, email_raw: str, code_raw: str) -> None:
    email = _normalize_email(email_raw)
    code = code_raw.strip()

    row = _get_latest_pending_email_code(db, user_id, "email_add", email)
    _verify_email_code_or_fail(db, row, "email_add", email, code)

    _ensure_email_not_in_use(db, email, user_id)

    user = _get_user_by_id_or_404(db, user_id)
    user.email = email
    user.email_verified_at = now_utc()

    db.commit()


def start_remove_email(db: Session, user_id) -> EmailMessageData:
    email = prepare_email_remove(db, user_id)
    return issue_email_code_message(db, user_id, "email_remove", email)


def confirm_remove_email(
    db: Session,
    user_id,
    code_raw: str | None = None,
    recovery_code_raw: str | None = None,
) -> None:
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
    user, email = prepare_password_reset_email_send(db, username_raw, email_raw)
    return issue_email_code_message(db, user.id, "password_reset", email)


def password_reset_email_verify(
    db: Session,
    username_raw: str,
    email_raw: str,
    code_raw: str,
):
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

    sess.consumed_at = now_utc()
    db.commit()
