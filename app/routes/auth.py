from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.deps import get_current_user
from app.email_sender import SmtpEmailSender, EmailNotConfigured
from app.schemas.auth import *
from app.services import auth_service
from app.services.common import ServiceError

router = APIRouter(prefix="/auth", tags=["auth"])

# for tests, will be removed later
active_sessions = auth_service.active_sessions
_now_utc = auth_service.now_utc
_as_utc = auth_service.as_utc
_generate_recovery_codes = auth_service.generate_recovery_codes
_generate_email_code = auth_service.generate_email_code
_mask_email = auth_service.mask_email
_get_user_lang = auth_service.get_user_lang
tokens = auth_service.tokens
SRPServerSession = auth_service.SRPServerSession


def _email_sender() -> SmtpEmailSender:
    return SmtpEmailSender()


def _err(status: int, code: str, detail: str | None = None):
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise HTTPException(status_code=status, detail=payload)


def _raise_service_error(exc: ServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _parse_hex_bytes(name: str, hex_str: str) -> bytes:
    try:
        return auth_service.parse_hex_bytes(name, hex_str)
    except ServiceError as exc:
        _raise_service_error(exc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/params", response_model=RegisterParamsOut)
def get_srp_params():
    constants = auth_service.get_srp_params()
    return RegisterParamsOut(N=constants["N"], g=constants["g"])


@router.post("/register", status_code=201, response_model=RegisterOut)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    try:
        codes_plain = auth_service.register_user(
            db, data.username, data.salt, data.verifier
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return RegisterOut(detail="registered", recovery_codes=codes_plain)


@router.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn, db: Session = Depends(get_db)):
    try:
        auth_service.SRPServerSession = SRPServerSession
        result = auth_service.start_login(db, body.username)
    except ServiceError as exc:
        _raise_service_error(exc)

    return LoginStartOut(
        salt=result.salt,
        B=result.B,
        N=result.N,
        g=result.g,
    )


@router.post("/login/finish", response_model=LoginFinishOut)
def login_finish(body: LoginFinishIn, db: Session = Depends(get_db)):
    try:
        result = auth_service.finish_login(
            db=db,
            username_raw=body.username,
            A=body.A,
            M1=body.M1,
            salt=body.salt,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return LoginFinishOut(
        M2=result.M2,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
    )


@router.post("/refresh")
def refresh_token(old_refresh: dict, db: Session = Depends(get_db)):
    try:
        return auth_service.refresh_access_token(db, old_refresh.get("refresh_token"))
    except ServiceError as exc:
        _raise_service_error(exc)


@router.post("/logout", response_model=GenericOk)
def logout(user=Depends(get_current_user), db: Session = Depends(get_db)):
    auth_service.logout_user(db, user.id)
    return GenericOk(detail="logged out")


@router.get("/me")
def get_me(user=Depends(get_current_user)):
    return auth_service.get_me_data(user)


@router.post("/email/start-add", response_model=GenericOk)
def email_start_add(
    body: EmailStartAddIn,
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        message = auth_service.start_add_email(db, user.id, str(body.email))
    except ServiceError as exc:
        _raise_service_error(exc)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, message.email, message.subject, message.text)
    except EmailNotConfigured as e:
        _err(503, "EMAIL_NOT_CONFIGURED", str(e))

    return GenericOk(detail="code_sent")


@router.post("/email/confirm-add", response_model=GenericOk)
def email_confirm_add(
    body: EmailConfirmIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        auth_service.confirm_add_email(db, user.id, str(body.email), body.code)
    except ServiceError as exc:
        _raise_service_error(exc)

    return GenericOk(detail="email_verified")


@router.post("/email/start-remove", response_model=GenericOk)
def email_start_remove(
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        message = auth_service.start_remove_email(db, user.id)
    except ServiceError as exc:
        _raise_service_error(exc)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, message.email, message.subject, message.text)
    except EmailNotConfigured as e:
        _err(503, "EMAIL_NOT_CONFIGURED", str(e))

    return GenericOk(detail="code_sent")


@router.post("/email/confirm-remove", response_model=GenericOk)
def email_confirm_remove(
    body: EmailRemoveConfirmIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        auth_service.confirm_remove_email(
            db=db,
            user_id=user.id,
            code_raw=body.code,
            recovery_code_raw=body.recovery_code,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return GenericOk(detail="email_removed")


@router.post("/password-reset/start", response_model=PasswordResetStartOut)
def password_reset_start(body: PasswordResetStartIn, db: Session = Depends(get_db)):
    try:
        result = auth_service.password_reset_start(db, body.username)
    except ServiceError as exc:
        _raise_service_error(exc)

    return PasswordResetStartOut(
        has_email=result.has_email,
        email=result.email,
        has_recovery=result.has_recovery,
    )


@router.post("/password-reset/email/send", response_model=GenericOk)
def password_reset_email_send(
    body: PasswordResetEmailSendIn,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
):
    try:
        message = auth_service.password_reset_email_send(
            db=db,
            username_raw=body.username,
            email_raw=str(body.email),
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    try:
        sender = _email_sender()
        bg.add_task(sender.send_text, message.email, message.subject, message.text)
    except EmailNotConfigured as e:
        _err(503, "EMAIL_NOT_CONFIGURED", str(e))

    return GenericOk(detail="code_sent")


@router.post("/password-reset/email/verify", response_model=PasswordResetVerifyOut)
def password_reset_email_verify(
    body: PasswordResetEmailVerifyIn,
    db: Session = Depends(get_db),
):
    try:
        reset_session_id = auth_service.password_reset_email_verify(
            db=db,
            username_raw=body.username,
            email_raw=str(body.email),
            code_raw=body.code,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return PasswordResetVerifyOut(reset_session_id=reset_session_id)


@router.post("/password-reset/recovery/verify", response_model=PasswordResetVerifyOut)
def password_reset_recovery_verify(
    body: PasswordResetRecoveryVerifyIn,
    db: Session = Depends(get_db),
):
    try:
        reset_session_id = auth_service.password_reset_recovery_verify(
            db=db,
            username_raw=body.username,
            recovery_code_raw=body.recovery_code,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return PasswordResetVerifyOut(reset_session_id=reset_session_id)


@router.post("/password-reset/finish", response_model=GenericOk)
def password_reset_finish(body: PasswordResetFinishIn, db: Session = Depends(get_db)):
    try:
        auth_service.password_reset_finish(
            db=db,
            reset_session_id=body.reset_session_id,
            new_salt_hex=body.new_salt,
            new_verifier_hex=body.new_verifier,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return GenericOk(detail="password_reset_ok")
