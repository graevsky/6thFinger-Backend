from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.email_sender import EmailNotConfigured, SmtpEmailSender
from app.schemas.auth import (
    EmailConfirmIn,
    EmailRemoveConfirmIn,
    EmailStartAddIn,
    GenericOk,
    LoginFinishIn,
    LoginFinishOut,
    LoginStartIn,
    LoginStartOut,
    PasswordResetEmailSendIn,
    PasswordResetEmailVerifyIn,
    PasswordResetFinishIn,
    PasswordResetRecoveryVerifyIn,
    PasswordResetStartIn,
    PasswordResetStartOut,
    PasswordResetVerifyOut,
    RegisterIn,
    RegisterOut,
    RegisterParamsOut,
)
from app.security.rate_limit import enforce_rate_limit
from app.services import auth_service
from app.services.common import ServiceError

router = APIRouter(prefix="/auth", tags=["auth"])


def _email_sender() -> SmtpEmailSender:
    """Create SMTP sender instance for email-based flows"""
    return SmtpEmailSender()


def _err(status: int, code: str, detail: str | None = None):
    """Raise a unified HTTP error payload used by auth endpoints"""
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise HTTPException(status_code=status, detail=payload)


def _raise_service_error(exc: ServiceError):
    """Convert service-layer error into FastAPI HTTPException"""
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _get_ready_email_sender() -> SmtpEmailSender:
    """
    Build and validate email sender before scheduling background send
    """
    try:
        sender = _email_sender()
        sender.ensure_ready()
        return sender
    except EmailNotConfigured as e:
        _err(503, "EMAIL_NOT_CONFIGURED", str(e))

def _rl_ip(request: Request, scope: str, limit: int, window_sec: int = 60) -> None:
    enforce_rate_limit(
        request=request,
        scope=scope,
        limit=limit,
        window_sec=window_sec,
    )


def _rl_subject(
    request: Request,
    scope: str,
    subject: str,
    limit: int,
    window_sec: int = 60,
) -> None:
    enforce_rate_limit(
        request=request,
        scope=scope,
        limit=limit,
        window_sec=window_sec,
        subject=subject,
    )


def _limit_register(request: Request, username: str) -> None:
    _rl_ip(request, "auth:register:ip", 10, 60)
    _rl_subject(request, "auth:register:user", username, 5, 300)


def _limit_login_start(request: Request, username: str) -> None:
    _rl_ip(request, "auth:login:start:ip", 30, 60)
    _rl_subject(request, "auth:login:start:user", username, 10, 60)


def _limit_login_finish(request: Request, username: str) -> None:
    _rl_ip(request, "auth:login:finish:ip", 30, 60)
    _rl_subject(request, "auth:login:finish:user", username, 10, 60)


def _limit_refresh(request: Request) -> None:
    _rl_ip(request, "auth:refresh:ip", 60, 60)


def _limit_user_email_flow(request: Request, user_id: str, scope: str) -> None:
    _rl_ip(request, f"{scope}:ip", 20, 60)
    _rl_subject(request, f"{scope}:user", user_id, 10, 60)


def _limit_password_reset_flow(request: Request, username: str, scope: str) -> None:
    _rl_ip(request, f"{scope}:ip", 15, 60)
    _rl_subject(request, f"{scope}:user", username, 5, 60)


@router.get("/params", response_model=RegisterParamsOut, summary="Get SRP parameters")
def get_srp_params():
    """Return public SRP constants required by the client during auth flow"""
    return auth_service.get_srp_params()


@router.post(
    "/register",
    status_code=201,
    response_model=RegisterOut,
    summary="Register new user",
)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    """
    Create a new user with SRP credentials.
    Returns generated recovery codes once.
    """
    _limit_register(request, data.username)

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


@router.post(
    "/login/start",
    response_model=LoginStartOut,
    summary="Start SRP login",
)
def login_start(body: LoginStartIn, request: Request, db: Session = Depends(get_db)):
    """Start SRP authentication and return server challenge values."""
    _limit_login_start(request, body.username)

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


@router.post(
    "/login/finish",
    response_model=LoginFinishOut,
    summary="Finish SRP login",
)
def login_finish(body: LoginFinishIn, request: Request, db: Session = Depends(get_db)):
    """
    Complete SRP authentication.
    On success returns access and refresh tokens.
    """
    _limit_login_finish(request, body.username)

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


@router.post(
    "/refresh",
    summary="Refresh access token",
)
def refresh_token(old_refresh: dict, request: Request, db: Session = Depends(get_db)):
    """Issue a new access token using a valid refresh token."""
    _limit_refresh(request)

    try:
        return auth_service.refresh_access_token(
            db,
            old_refresh.get("refresh_token"),
        )
    except ServiceError as exc:
        _raise_service_error(exc)


@router.post(
    "/logout",
    response_model=GenericOk,
    summary="Logout current user",
)
def logout(request: Request, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Revoke all active token records for the current user.
    """
    _limit_user_email_flow(request, str(user.id), "auth:logout")

    auth_service.logout_user(db, user.id)
    return GenericOk(detail="logged out")


@router.get(
    "/me",
    summary="Get current user",
)
def get_me(user=Depends(get_current_user)):
    """Return basic profile data for the authenticated user."""
    return auth_service.get_me_data(user)


@router.post(
    "/email/start-add",
    response_model=GenericOk,
    summary="Send email add confirmation code",
)
def email_start_add(
    body: EmailStartAddIn,
    request: Request,
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Start verified email attachment flow.
    Creates a one-time code and sends it to the requested email address.
    """
    try:
        email = auth_service.prepare_email_add(db, user.id, str(body.email))
    except ServiceError as exc:
        _raise_service_error(exc)

    sender = _get_ready_email_sender()
    message = auth_service.issue_email_code_message(db, user.id, "email_add", email)
    bg.add_task(sender.send_text, message.email, message.subject, message.text)

    return GenericOk(detail="code_sent")


@router.post(
    "/email/confirm-add",
    response_model=GenericOk,
    summary="Confirm email add",
)
def email_confirm_add(
    body: EmailConfirmIn,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify email code and attach verified email to the current user."""
    _limit_user_email_flow(request, str(user.id), "auth:email:confirm_add")

    try:
        auth_service.confirm_add_email(db, user.id, str(body.email), body.code)
    except ServiceError as exc:
        _raise_service_error(exc)

    return GenericOk(detail="email_verified")


@router.post(
    "/email/start-remove",
    response_model=GenericOk,
    summary="Send email removal confirmation code",
)
def email_start_remove(
    request: Request,
    bg: BackgroundTasks,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Start verified email removal flow.
    Sends confirmation code to the currently verified email address.
    """
    _limit_user_email_flow(request, str(user.id), "auth:email:start_remove")

    try:
        email = auth_service.prepare_email_remove(db, user.id)
    except ServiceError as exc:
        _raise_service_error(exc)

    sender = _get_ready_email_sender()
    message = auth_service.issue_email_code_message(db, user.id, "email_remove", email)
    bg.add_task(sender.send_text, message.email, message.subject, message.text)

    return GenericOk(detail="code_sent")


@router.post(
    "/email/confirm-remove",
    response_model=GenericOk,
    summary="Confirm email removal",
)
def email_confirm_remove(
    body: EmailRemoveConfirmIn,
    request: Request,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Remove verified email from the current account.
    Confirmation can be done either by email code or by recovery code.
    """
    _limit_user_email_flow(request, str(user.id), "auth:email:confirm_remove")

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


@router.post(
    "/password-reset/start",
    response_model=PasswordResetStartOut,
    summary="Start password reset flow",
)
def password_reset_start(body: PasswordResetStartIn, request: Request, db: Session = Depends(get_db)):
    """
    Check which password reset methods are available for a user.
    Returns whether verified email and unused recovery codes exist.
    """
    _limit_password_reset_flow(request, body.username, "auth:password_reset:start")

    try:
        result = auth_service.password_reset_start(db, body.username)
    except ServiceError as exc:
        _raise_service_error(exc)

    return PasswordResetStartOut(
        has_email=result.has_email,
        email=result.email,
        has_recovery=result.has_recovery,
    )


@router.post(
    "/password-reset/email/send",
    response_model=GenericOk,
    summary="Send password reset email code",
)
def password_reset_email_send(
    body: PasswordResetEmailSendIn,
    request: Request,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Send one-time password reset code to the verified email.
    """
    _limit_password_reset_flow(
        request, body.username, "auth:password_reset:email_send"
    )

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


@router.post(
    "/password-reset/email/verify",
    response_model=PasswordResetVerifyOut,
    summary="Verify password reset email code",
)
def password_reset_email_verify(
    body: PasswordResetEmailVerifyIn,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Verify password reset email code.
    On success creates short-lived reset session used by the finish step.
    """
    _limit_password_reset_flow(
        request, body.username, "auth:password_reset:email_verify"
    )

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


@router.post(
    "/password-reset/recovery/verify",
    response_model=PasswordResetVerifyOut,
    summary="Verify password reset recovery code",
)
def password_reset_recovery_verify(
    body: PasswordResetRecoveryVerifyIn,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Verify backup recovery code for password reset.
    On success creates short-lived reset session used by the finish step.
    """
    _limit_password_reset_flow(
        request, body.username, "auth:password_reset:recovery_verify"
    )

    try:
        reset_session_id = auth_service.password_reset_recovery_verify(
            db=db,
            username_raw=body.username,
            recovery_code_raw=body.recovery_code,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return PasswordResetVerifyOut(reset_session_id=reset_session_id)


@router.post(
    "/password-reset/finish",
    response_model=GenericOk,
    summary="Finish password reset",
)
def password_reset_finish(
    body: PasswordResetFinishIn,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Replace SRP credentials using a valid reset session.
    """
    _rl_ip(request, "auth:password_reset:finish:ip", 10, 60)

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
