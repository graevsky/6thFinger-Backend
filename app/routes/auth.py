from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.deps import get_current_user, get_db
from app.email_sender import SmtpEmailSender, EmailNotConfigured
from app.schemas.auth import *
from app.services import auth_service
from app.services.common import ServiceError
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["auth"])


def _email_sender() -> SmtpEmailSender:
    return SmtpEmailSender()


def _err(status: int, code: str, detail: str | None = None):
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise HTTPException(status_code=status, detail=payload)


def _raise_service_error(exc: ServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _get_ready_email_sender() -> SmtpEmailSender:
    try:
        sender = _email_sender()
        sender.ensure_ready()
        return sender
    except EmailNotConfigured as e:
        _err(503, "EMAIL_NOT_CONFIGURED", str(e))


@router.get("/params", response_model=RegisterParamsOut)
def get_srp_params():
    constants = auth_service.get_srp_params()
    return RegisterParamsOut(N=constants["N"], g=constants["g"])


@router.post("/register", status_code=201, response_model=RegisterOut)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    try:
        codes_plain = auth_service.register_user(
            db,
            data.username,
            data.salt,
            data.verifier,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return RegisterOut(detail="registered", recovery_codes=codes_plain)


@router.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn, db: Session = Depends(get_db)):
    try:
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
        return auth_service.refresh_access_token(
            db,
            old_refresh.get("refresh_token"),
        )
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
        email = auth_service.prepare_email_add(db, user.id, str(body.email))
    except ServiceError as exc:
        _raise_service_error(exc)

    sender = _get_ready_email_sender()
    message = auth_service.issue_email_code_message(db, user.id, "email_add", email)
    bg.add_task(sender.send_text, message.email, message.subject, message.text)

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
        email = auth_service.prepare_email_remove(db, user.id)
    except ServiceError as exc:
        _raise_service_error(exc)

    sender = _get_ready_email_sender()
    message = auth_service.issue_email_code_message(db, user.id, "email_remove", email)
    bg.add_task(sender.send_text, message.email, message.subject, message.text)

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
        user, email = auth_service.prepare_password_reset_email_send(
            db=db,
            username_raw=body.username,
            email_raw=str(body.email),
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    sender = _get_ready_email_sender()
    message = auth_service.issue_email_code_message(
        db,
        user.id,
        "password_reset",
        email,
    )
    bg.add_task(sender.send_text, message.email, message.subject, message.text)

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
