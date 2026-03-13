import hashlib
import datetime
import secrets
import string
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from srptools import SRPContext, SRPServerSession
from srptools.constants import PRIME_2048, PRIME_2048_GEN

from app import db
from app.email_sender import SmtpEmailSender, EmailNotConfigured
from app.models.email_code import EmailCode
from app.models.recovery_code import RecoveryCode
from app.schemas.auth import *
from app.security import srp as srp_utils, tokens
from app.db import SessionLocal
from app.models.user import User
from app.models.token import Token
from app.models.password_reset_session import PasswordResetSession
from app.deps import get_current_user
from app.security.hashing import hash_recovery_code, hash_email_code
from app.models.app_settings import AppSettings
from app.locale.i18n_email import build_email, normalize_lang

router = APIRouter(prefix="/auth", tags=["auth"])

active_sessions: dict[str, SRPServerSession] = {}
PRIME = PRIME_2048
GENERATOR = PRIME_2048_GEN

EMAIL_CODE_TTL_MIN = 10
EMAIL_CODE_MAX_ATTEMPTS = 5
EMAIL_CODE_RESEND_COOLDOWN_SEC = 60

RESET_SESSION_TTL_MIN = 15


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_hex_bytes(name: str, hex_str: str) -> bytes:
    try:
        v = hex_str.strip().lower()
        if len(v) % 2 != 0:
            v = "0" + v
        return bytes.fromhex(v)
    except Exception:
        return HTTPException(status_code=400, detail=f"{name} must be hex")


def _generate_recovery_codes(n: int = 10) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    codes: list[str] = []
    for _ in range(n):
        parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
        codes.append("-".join(parts))
    return codes


def _generate_email_code() -> str:
    return "".join(secrets.choice(string.digits) for _ in range(6))


def _email_sender() -> SmtpEmailSender:
    return SmtpEmailSender()


def _get_user_lang(db: Session, user_id) -> str:
    s = db.query(AppSettings).filter_by(user_id=user_id).first()
    if not s or not isinstance(s.payload, dict):
        return "en"
    return normalize_lang(s.payload.get("lang"), default="en")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/params", response_model=RegisterParamsOut)
def get_srp_params():
    constants = srp_utils.get_constants()
    return RegisterParamsOut(N=constants["N"], g=constants["g"])


@router.post("/register", status_code=201, response_model=RegisterOut)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    username = data.username.lower().strip()
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(
            status_code=409,
            detail={"error": "USERNAME_TAKEN", "detail": "Username already exists"},
        )

    salt = _parse_hex_bytes("salt", data.salt)
    verifier = _parse_hex_bytes("verifier", data.verifier)

    user = User(username=username, srp_salt=salt, srp_verifier=verifier)
    db.add(user)
    db.commit()
    db.refresh(user)

    codes_plain = _generate_recovery_codes(10)
    rows = [
        RecoveryCode(user_id=user.id, code_hash=hash_recovery_code(c))
        for c in codes_plain
    ]
    db.add_all(rows)
    db.commit()

    return RegisterOut(detail="registered", recovery_codes=codes_plain)


@router.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn, db: Session = Depends(get_db)):
    username = body.username.lower().strip()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": "USER_NOT_FOUND", "detail": "User not found"},
        )

    verifier_hex = user.srp_verifier.hex()
    ctx = SRPContext(username, "", prime=PRIME, generator=GENERATOR)
    server_session = SRPServerSession(ctx, verifier_hex)
    active_sessions[username] = server_session

    return LoginStartOut(
        salt=user.srp_salt.hex(),
        B=server_session.public,
        N=PRIME,
        g=GENERATOR,
    )


@router.post("/login/finish", response_model=LoginFinishOut)
def login_finish(body: LoginFinishIn, db: Session = Depends(get_db)):
    username = body.username.lower().strip()
    session = active_sessions.get(username)
    if not session:
        raise HTTPException(status_code=400, detail="No active session")

    try:
        session.process(body.A, body.salt)
        client_M1 = body.M1.encode("ascii")
        if not session.verify_proof(client_M1):
            raise ValueError("Proof mismatch")
    except Exception:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "WRONG_PASSWORD",
                "detail": "Invalid username or password",
            },
        )

    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": "USER_NOT_FOUND", "detail": "User not found"},
        )

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
        )
    )
    db.commit()
    active_sessions.pop(username, None)

    return LoginFinishOut(
        M2=session.key_proof_hash.decode("ascii"),
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh")
def refresh_token(old_refresh: dict, db: Session = Depends(get_db)):
    token_str = old_refresh.get("refresh_token")
    if not token_str:
        raise HTTPException(status_code=400, detail="Missing token")

    payload = tokens.verify_token(token_str)
    if not payload or payload.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = hashlib.sha256(token_str.encode()).digest()
    db_token = db.query(Token).filter_by(token_hash=token_hash, revoked_at=None).first()
    if not db_token:
        raise HTTPException(status_code=401, detail="Token revoked or missing")

    new_access = tokens.create_access_token({"sub": payload["sub"]})
    return {"access_token": new_access}


@router.post("/logout", response_model=GenericOk)
def logout(user=Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Token).filter_by(user_id=user.id, revoked_at=None).update(
        {"revoked_at": _now_utc()}
    )
    db.commit()
    return GenericOk(detail="logged out")


@router.get("/me")
def get_me(user=Depends(get_current_user)):
    return {"id": str(user.id), "username": user.username}


@router.post("/email/start-add", response_model=GenericOk)
def email_start_add(
    body: EmailStartAddIn,
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    email = body.email.lower().strip()

    other = db.query(User).filter(User.email == email, User.id != user.id).first()
    if other:
        raise HTTPException(status_code=409, detail="Email already in use")

    cutoff = _now_utc() - datetime.timedelta(seconds=EMAIL_CODE_RESEND_COOLDOWN_SEC)
    recent = (
        db.query(EmailCode)
        .filter_by(user_id=user.id, purpose="email_add", target_email=email)
        .filter(EmailCode.created_at >= cutoff)
        .first()
    )
    if recent:
        raise HTTPException(status_code=429, detail="Too many requests. Try later.")

    db.query(EmailCode).filter_by(
        user_id=user.id, purpose="email_add", target_email=email, consumed_at=None
    ).update({"consumed_at": _now_utc()})

    code_plain = _generate_email_code()
    expires = _now_utc() + datetime.timedelta(minutes=EMAIL_CODE_TTL_MIN)

    row = EmailCode(
        user_id=user.id,
        purpose="email_add",
        target_email=email,
        code_hash=hash_email_code("email_add", code_plain, email),
        expires_at=expires,
        attempts=0,
    )
    db.add(row)
    db.commit()

    lang = _get_user_lang(db, user.id)
    subject, text = build_email(lang, "email_add", code_plain, EMAIL_CODE_TTL_MIN)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, email, subject, text)
    except EmailNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))

    return GenericOk(detail="code_sent")


@router.post("/email/confirm-add", response_model=GenericOk)
def email_confirm_add(
    body: EmailConfirmIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    email = body.email.lower().strip()
    code = body.code.strip()

    row = (
        db.query(EmailCode)
        .filter_by(
            user_id=user.id, purpose="email_add", target_email=email, consumed_at=None
        )
        .order_by(EmailCode.created_at.desc())
        .first()
    )
    if not row:
        raise HTTPException(status_code=400, detail="No pending code")

    if row.expires_at < _now_utc():
        raise HTTPException(status_code=400, detail="Code expired")

    if row.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts")

    expected = hash_email_code("email_add", code, email)
    if row.code_hash != expected:
        row.attempts += 1
        db.commit()
        raise HTTPException(status_code=400, detail="Wrong code")

    row.consumed_at = _now_utc()
    row.attempts += 1

    other = db.query(User).filter(User.email == email, User.id != user.id).first()
    if other:
        raise HTTPException(status_code=409, detail="Email already in use")

    u = db.query(User).filter_by(id=user.id).first()
    u.email = email
    u.email_verified_at = _now_utc()

    db.commit()
    return GenericOk(detail="email_verified")


@router.post("/email/start-remove", response_model=GenericOk)
def email_start_remove(
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter_by(id=user.id).first()
    if not u.email or not u.email_verified_at:
        raise HTTPException(status_code=400, detail="No verified email")

    email = u.email.lower().strip()

    cutoff = _now_utc() - datetime.timedelta(seconds=EMAIL_CODE_RESEND_COOLDOWN_SEC)
    recent = (
        db.query(EmailCode)
        .filter_by(user_id=u.id, purpose="email_remove", target_email=email)
        .filter(EmailCode.created_at >= cutoff)
        .first()
    )
    if recent:
        raise HTTPException(status_code=429, detail="Too many requests. Try later.")

    db.query(EmailCode).filter_by(
        user_id=u.id, purpose="email_remove", target_email=email, consumed_at=None
    ).update({"consumed_at": _now_utc()})

    code_plain = _generate_email_code()
    expires = _now_utc() + datetime.timedelta(minutes=EMAIL_CODE_TTL_MIN)

    row = EmailCode(
        user_id=u.id,
        purpose="email_remove",
        target_email=email,
        code_hash=hash_email_code("email_remove", code_plain, email),
        expires_at=expires,
        attempts=0,
    )
    db.add(row)
    db.commit()

    lang = _get_user_lang(db, u.id)
    subject, text = build_email(lang, "email_remove", code_plain, EMAIL_CODE_TTL_MIN)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, email, subject, text)
    except EmailNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))

    return GenericOk(detail="code_sent")


@router.post("/email/confirm-remove", response_model=GenericOk)
def email_confirm_remove(
    body: EmailRemoveConfirmIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter_by(id=user.id).first()
    if not u.email or not u.email_verified_at:
        raise HTTPException(status_code=400, detail="No verified email")

    email = u.email.lower().strip()

    if body.code:
        code = body.code.strip()
        row = (
            db.query(EmailCode)
            .filter_by(
                user_id=u.id,
                purpose="email_remove",
                target_email=email,
                consumed_at=None,
            )
            .order_by(EmailCode.created_at.desc())
            .first()
        )
        if not row:
            raise HTTPException(status_code=400, detail="No pending code")
        if row.expires_at < _now_utc():
            raise HTTPException(status_code=400, detail="Code expired")
        if row.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Too many attempts")

        expected = hash_email_code("email_remove", code, email)
        if row.code_hash != expected:
            row.attempts += 1
            db.commit()
            raise HTTPException(status_code=400, detail="Wrong code")

        row.consumed_at = _now_utc()
        row.attempts += 1
        u.email = None
        u.email_verified_at = None
        db.commit()
        return GenericOk(detail="email_removed")

    if body.recovery_code:
        rc = body.recovery_code.strip().upper()
        digest = hash_recovery_code(rc)
        rec = (
            db.query(RecoveryCode)
            .filter_by(user_id=u.id, code_hash=digest, used_at=None)
            .first()
        )
        if not rec:
            raise HTTPException(status_code=400, detail="Wrong recovery code")
        rec.used_at = _now_utc()
        u.email = None
        u.email_verified_at = None
        db.commit()
        return GenericOk(detail="email_removed")

    raise HTTPException(status_code=400, detail="Provide code or recovery_code")


@router.post("/password-reset/start", response_model=PasswordResetStartOut)
def password_reset_start(body: PasswordResetStartIn, db: Session = Depends(get_db)):
    username = body.username.lower().strip()
    u = db.query(User).filter_by(username=username).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    has_email = bool(u.email and u.email_verified_at)
    return PasswordResetStartOut(
        has_email=has_email,
        email=(u.email if has_email else None),
        has_recovery=True,
    )


@router.post("/password-reset/email/send", response_model=GenericOk)
def password_reset_email_send(
    body: PasswordResetEmailSendIn,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
):
    username = body.username.lower().strip()
    email = body.email.lower().strip()

    u = db.query(User).filter_by(username=username).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if not u.email or not u.email_verified_at:
        raise HTTPException(status_code=400, detail="Email not set")

    if u.email.lower().strip() != email:
        raise HTTPException(status_code=400, detail="Email mismatch")

    cutoff = _now_utc() - datetime.timedelta(seconds=EMAIL_CODE_RESEND_COOLDOWN_SEC)
    recent = (
        db.query(EmailCode)
        .filter_by(user_id=u.id, purpose="password_reset", target_email=email)
        .filter(EmailCode.created_at >= cutoff)
        .first()
    )
    if recent:
        raise HTTPException(status_code=429, detail="Too many requests. Try later.")

    db.query(EmailCode).filter_by(
        user_id=u.id, purpose="password_reset", target_email=email, consumed_at=None
    ).update({"consumed_at": _now_utc()})

    code_plain = _generate_email_code()
    expires = _now_utc() + datetime.timedelta(minutes=EMAIL_CODE_TTL_MIN)

    row = EmailCode(
        user_id=u.id,
        purpose="password_reset",
        target_email=email,
        code_hash=hash_email_code("password_reset", code_plain, email),
        expires_at=expires,
        attempts=0,
    )
    db.add(row)
    db.commit()

    lang = _get_user_lang(db, u.id)
    subject, text = build_email(lang, "password_reset", code_plain, EMAIL_CODE_TTL_MIN)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, email, subject, text)
    except EmailNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))

    return GenericOk(detail="code_sent")


@router.post("/password-reset/email/verify", response_model=PasswordResetVerifyOut)
def password_reset_email_verify(
    body: PasswordResetEmailVerifyIn,
    db: Session = Depends(get_db),
):
    username = body.username.lower().strip()
    email = body.email.lower().strip()
    code = body.code.strip()

    u = db.query(User).filter_by(username=username).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if not u.email or not u.email_verified_at:
        raise HTTPException(status_code=400, detail="Email not set")

    if u.email.lower().strip() != email:
        raise HTTPException(status_code=400, detail="Email mismatch")

    row = (
        db.query(EmailCode)
        .filter_by(
            user_id=u.id, purpose="password_reset", target_email=email, consumed_at=None
        )
        .order_by(EmailCode.created_at.desc())
        .first()
    )
    if not row:
        raise HTTPException(status_code=400, detail="No pending code")
    if row.expires_at < _now_utc():
        raise HTTPException(status_code=400, detail="Code expired")
    if row.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts")

    expected = hash_email_code("password_reset", code, email)
    if row.code_hash != expected:
        row.attempts += 1
        db.commit()
        raise HTTPException(status_code=400, detail="Wrong code")

    row.consumed_at = _now_utc()
    row.attempts += 1

    sess = PasswordResetSession(
        user_id=u.id,
        method="email",
        verified_at=_now_utc(),
        expires_at=_now_utc() + datetime.timedelta(minutes=RESET_SESSION_TTL_MIN),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    return PasswordResetVerifyOut(reset_session_id=sess.id)


@router.post("/password-reset/recovery/verify", response_model=PasswordResetVerifyOut)
def password_reset_recovery_verify(
    body: PasswordResetRecoveryVerifyIn,
    db: Session = Depends(get_db),
):
    username = body.username.lower().strip()
    code_plain = body.recovery_code.strip().upper()

    u = db.query(User).filter_by(username=username).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    digest = hash_recovery_code(code_plain)

    rec = (
        db.query(RecoveryCode)
        .filter_by(user_id=u.id, code_hash=digest, used_at=None)
        .first()
    )
    if not rec:
        raise HTTPException(status_code=400, detail="Wrong recovery code")

    rec.used_at = _now_utc()

    sess = PasswordResetSession(
        user_id=u.id,
        method="recovery_code",
        verified_at=_now_utc(),
        expires_at=_now_utc() + datetime.timedelta(minutes=RESET_SESSION_TTL_MIN),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    return PasswordResetVerifyOut(reset_session_id=sess.id)


@router.post("/password-reset/finish", response_model=GenericOk)
def password_reset_finish(body: PasswordResetFinishIn, db: Session = Depends(get_db)):
    sess = db.query(PasswordResetSession).filter_by(id=body.reset_session_id).first()
    if not sess:
        raise HTTPException(status_code=400, detail="Invalid session")

    if sess.consumed_at is not None:
        raise HTTPException(status_code=400, detail="Session already used")

    if sess.expires_at < _now_utc():
        raise HTTPException(status_code=400, detail="Session expired")

    u = db.query(User).filter_by(id=sess.user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    new_salt = _parse_hex_bytes("new_salt", body.new_salt)
    new_verifier = _parse_hex_bytes("new_verifier", body.new_verifier)

    u.srp_salt = new_salt
    u.srp_verifier = new_verifier

    sess.consumed_at = _now_utc()
    db.commit()

    return GenericOk(detail="password_reset_ok")
