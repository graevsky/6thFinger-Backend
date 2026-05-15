import datetime as dt
import uuid

from app.email_sender import EmailNotConfigured
from app.models.email_code import EmailCode
from app.models.password_reset_session import PasswordResetSession
from app.models.user import User
from tests.factories import (
    create_app_settings,
    create_email_code,
    create_password_reset_session,
    create_recovery_code,
)

EMAIL_DISABLED_DETAIL = "Email sending disabled (EMAIL_ENABLED=false)"


def test_password_reset_start_returns_404_when_user_not_found(client):
    response = client.post(
        "/auth/password-reset/start",
        json={"username": "missing_user"},
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_password_reset_start_returns_masked_email_when_verified_email_exists(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )
    create_recovery_code(
        db_session, user_id=user.id, plain_code="ABCD-EFGH-IJKL", used=False
    )

    response = client.post(
        "/auth/password-reset/start",
        json={"username": "  john_doe  "},
    )

    assert response.status_code == 200
    assert response.json() == {
        "has_email": True,
        "email": "j*******@example.com",
        "has_recovery": True,
    }


def test_password_reset_start_hides_email_when_email_disabled(
    client,
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )
    create_recovery_code(
        db_session, user_id=user.id, plain_code="ABCD-EFGH-IJKL", used=False
    )
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/password-reset/start",
        json={"username": "john_doe"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "has_email": False,
        "email": None,
        "has_recovery": True,
    }


def test_password_reset_start_returns_no_email_when_user_has_no_verified_email(
    client,
    user_factory,
):
    user_factory(username="john_doe", email=None, verified=False)

    response = client.post(
        "/auth/password-reset/start",
        json={"username": "john_doe"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "has_email": False,
        "email": None,
        "has_recovery": False,
    }


def test_password_reset_email_send_returns_404_when_user_not_found(client):
    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "missing_user", "email": "john_doe@example.com"},
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_password_reset_email_send_returns_400_when_email_not_set(
    client,
    user_factory,
):
    user_factory(username="john_doe", email=None, verified=False)

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "john_doe", "email": "john_doe@example.com"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_NOT_SET"
    assert data["detail"]["detail"] == "Email not set"


def test_password_reset_email_send_returns_400_when_email_mismatch(
    client,
    user_factory,
):
    user_factory(username="john_doe", email="john_doe@example.com", verified=True)

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "john_doe", "email": "other@example.com"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_MISMATCH"
    assert data["detail"]["detail"] == "Email mismatch"


def test_password_reset_email_send_returns_429_when_cooldown_is_active(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "john_doe", "email": "john_doe@example.com"},
    )

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_REQUESTS"
    assert data["detail"]["detail"] == "Too many requests. Try later."


def test_password_reset_email_send_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "john_doe", "email": "john_doe@example.com"},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="password_reset",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_password_reset_email_send_returns_503_when_sender_not_configured(
    client,
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    def raise_not_configured():
        raise EmailNotConfigured("password reset smtp disabled")

    monkeypatch.setattr("app.routes.auth._email_sender", raise_not_configured)

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "john_doe", "email": "john_doe@example.com"},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_NOT_CONFIGURED"
    assert data["detail"]["detail"] == "password reset smtp disabled"

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="password_reset",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_password_reset_email_send_success_creates_code_and_uses_fake_sender(
    client,
    db_session,
    user_factory,
    fake_email_sender,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )
    create_app_settings(db_session, user.id, payload={"language": "ru"})

    response = client.post(
        "/auth/password-reset/email/send",
        json={"username": "  john_doe  ", "email": "john_doe@Example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "code_sent"}

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="password_reset",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 1
    assert rows[0].attempts == 0
    assert rows[0].consumed_at is None

    assert len(fake_email_sender.sent) == 1
    sent = fake_email_sender.sent[0]
    assert sent["email"] == "john_doe@example.com"
    assert sent["subject"] == "Восстановление пароля"
    assert "Добрый день, john_doe!" in sent["text"]
    assert "Добрый день, john_doe!" in sent["html"]
    assert "Код восстановления: " in sent["text"]
    assert "Срок действия: 10 минут." in sent["text"]
    assert "С уважением,\nкоманда Prothesis.ru" in sent["text"]
    assert "Prothesis.ru: https://prothesis.ru" in sent["text"]
    assert (
        "Руководство: https://drive.google.com/file/d/1A2usxykovqEe099k2ItJ9acGboUhyZ13/view?usp=sharing"
        in sent["text"]
    )
    assert 'href="https://prothesis.ru"' in sent["html"]
    assert (
        'href="https://drive.google.com/file/d/1A2usxykovqEe099k2ItJ9acGboUhyZ13/view?usp=sharing"'
        in sent["html"]
    )
    assert "Добрый день, john_doe!" in sent["html"]


def test_password_reset_email_verify_returns_404_when_user_not_found(client):
    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "missing_user",
            "email": "john_doe@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_password_reset_email_verify_returns_400_when_email_not_set(
    client,
    user_factory,
):
    user_factory(username="john_doe", email=None, verified=False)

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_NOT_SET"
    assert data["detail"]["detail"] == "Email not set"


def test_password_reset_email_verify_returns_400_when_email_mismatch(
    client,
    user_factory,
):
    user_factory(username="john_doe", email="john_doe@example.com", verified=True)

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "other@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_MISMATCH"
    assert data["detail"]["detail"] == "Email mismatch"


def test_password_reset_email_verify_returns_400_when_no_pending_code(
    client,
    user_factory,
):
    user_factory(username="john_doe", email="john_doe@example.com", verified=True)

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "NO_PENDING_CODE"
    assert data["detail"]["detail"] == "No pending code"


def test_password_reset_email_verify_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )
    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": code,
        },
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    db_session.refresh(row)
    sessions = db_session.query(PasswordResetSession).filter_by(user_id=user.id).all()
    assert row.consumed_at is None
    assert row.attempts == 0
    assert len(sessions) == 0


def test_password_reset_email_verify_returns_400_when_code_expired(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "CODE_EXPIRED"
    assert data["detail"]["detail"] == "Code expired"


def test_password_reset_email_verify_returns_429_when_attempt_limit_reached(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=5,
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": "123456",
        },
    )

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_ATTEMPTS"
    assert data["detail"]["detail"] == "Too many attempts"


def test_password_reset_email_verify_returns_400_and_increments_attempts_on_wrong_code(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    row, _ = create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=0,
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "john_doe",
            "email": "john_doe@example.com",
            "code": "654321",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "WRONG_CODE"
    assert data["detail"]["detail"] == "Wrong code"

    db_session.refresh(row)
    assert row.attempts == 1
    assert row.consumed_at is None


def test_password_reset_email_verify_success_creates_reset_session_and_consumes_code(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe", email="john_doe@example.com", verified=True
    )

    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="password_reset",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/email/verify",
        json={
            "username": "  john_doe  ",
            "email": "john_doe@Example.com",
            "code": code,
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert "reset_session_id" in data

    db_session.refresh(row)
    sessions = db_session.query(PasswordResetSession).filter_by(user_id=user.id).all()

    assert row.consumed_at is not None
    assert row.attempts == 1
    assert len(sessions) == 1
    assert sessions[0].method == "email"
    assert sessions[0].verified_at is not None
    assert sessions[0].expires_at is not None


def test_password_reset_recovery_verify_returns_404_when_user_not_found(client):
    response = client.post(
        "/auth/password-reset/recovery/verify",
        json={
            "username": "missing_user",
            "recovery_code": "ABCD-EFGH-IJKL",
        },
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_password_reset_recovery_verify_returns_400_for_wrong_recovery_code(
    client,
    user_factory,
):
    user_factory(username="john_doe")

    response = client.post(
        "/auth/password-reset/recovery/verify",
        json={
            "username": "john_doe",
            "recovery_code": "WRONG-CODE-0000",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "WRONG_RECOVERY_CODE"
    assert data["detail"]["detail"] == "Wrong recovery code"


def test_password_reset_recovery_verify_success_marks_code_used_and_creates_session(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")

    row, recovery_code = create_recovery_code(
        db_session,
        user_id=user.id,
        plain_code="ABCD-EFGH-IJKL",
        used=False,
    )

    response = client.post(
        "/auth/password-reset/recovery/verify",
        json={
            "username": "  john_doe  ",
            "recovery_code": recovery_code.lower(),
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert "reset_session_id" in data

    db_session.refresh(row)
    sessions = db_session.query(PasswordResetSession).filter_by(user_id=user.id).all()

    assert row.used_at is not None
    assert len(sessions) == 1
    assert sessions[0].method == "recovery_code"


def test_password_reset_finish_returns_400_for_invalid_session(client):
    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(uuid.uuid4()),
            "new_salt": "0abc",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "INVALID_SESSION"
    assert data["detail"]["detail"] == "Invalid session"


def test_password_reset_finish_returns_400_when_session_already_used(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        consumed=True,
    )

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "0abc",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "SESSION_ALREADY_USED"
    assert data["detail"]["detail"] == "Session already used"


def test_password_reset_finish_returns_400_when_session_expired(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "0abc",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "SESSION_EXPIRED"
    assert data["detail"]["detail"] == "Session expired"


def test_password_reset_finish_returns_404_when_user_not_found(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        consumed=False,
    )

    sess.user_id = uuid.uuid4()
    db_session.commit()
    db_session.refresh(sess)

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "0abc",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_password_reset_finish_returns_400_for_bad_new_salt(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "not-hex",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "BAD_HEX"
    assert data["detail"]["detail"] == "new_salt must be hex"


def test_password_reset_finish_returns_400_for_bad_new_verifier(
    client,
    db_session,
    user_factory,
):
    user = user_factory(username="john_doe")
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "0abc",
            "new_verifier": "not-hex",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "BAD_HEX"
    assert data["detail"]["detail"] == "new_verifier must be hex"


def test_password_reset_finish_success_updates_user_credentials_and_consumes_session(
    client,
    db_session,
    user_factory,
):
    user = user_factory(
        username="john_doe",
        srp_salt=bytes.fromhex("aaaa"),
        srp_verifier=bytes.fromhex("bbbb"),
    )
    sess = create_password_reset_session(
        db_session,
        user_id=user.id,
        consumed=False,
    )

    response = client.post(
        "/auth/password-reset/finish",
        json={
            "reset_session_id": str(sess.id),
            "new_salt": "0abc",
            "new_verifier": "abcd1234",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "password_reset_ok"}

    db_session.refresh(sess)
    updated_user = db_session.query(User).filter_by(id=user.id).first()

    assert updated_user.srp_salt == bytes.fromhex("0abc")
    assert updated_user.srp_verifier == bytes.fromhex("abcd1234")
    assert sess.consumed_at is not None
