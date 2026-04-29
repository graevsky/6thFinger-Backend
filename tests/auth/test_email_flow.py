import datetime as dt

from app.email_sender import EmailNotConfigured
from app.models.email_code import EmailCode
from app.models.recovery_code import RecoveryCode
from app.models.user import User
from tests.factories import create_app_settings, create_email_code, create_recovery_code

EMAIL_DISABLED_DETAIL = "Email sending disabled (EMAIL_ENABLED=false)"


def test_email_start_add_success_creates_new_code_consumes_old_and_uses_fake_sender(
    client,
    db_session,
    user_factory,
    auth_as,
    fake_email_sender,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    create_app_settings(db_session, user.id, payload={"language": "ru"})
    old_row, _ = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="111111",
        consumed=False,
    )
    old_row.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    db_session.commit()

    response = client.post(
        "/auth/email/start-add",
        json={"email": "john_doe@Example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "code_sent"}

    db_session.refresh(old_row)
    assert old_row.consumed_at is not None

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id, purpose="email_add", target_email="john_doe@example.com"
        )
        .all()
    )
    assert len(rows) == 2

    new_rows = [row for row in rows if row.id != old_row.id]
    assert len(new_rows) == 1
    assert new_rows[0].consumed_at is None
    assert new_rows[0].attempts == 0

    assert len(fake_email_sender.sent) == 1
    sent = fake_email_sender.sent[0]
    assert sent["email"] == "john_doe@example.com"
    assert sent["subject"] == "Подтверждение почты"
    assert "Срок действия: 10 минут." in sent["text"]


def test_email_start_add_returns_409_when_email_is_used_by_another_user(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    other = user_factory(username="jane_doe", email="taken@example.com", verified=True)
    auth_as(user)

    response = client.post(
        "/auth/email/start-add",
        json={"email": "taken@example.com"},
    )

    assert response.status_code == 409
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_IN_USE"
    assert data["detail"]["detail"] == "Email already in use"


def test_email_start_add_returns_429_when_cooldown_is_active(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="111111",
        consumed=False,
    )

    response = client.post(
        "/auth/email/start-add",
        json={"email": "john_doe@example.com"},
    )

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_REQUESTS"
    assert data["detail"]["detail"] == "Too many requests. Try later."


def test_email_start_add_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="john_doe")
    auth_as(user)
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/email/start-add",
        json={"email": "john_doe@example.com"},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="email_add",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_email_start_add_returns_503_when_email_sender_not_configured(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    def raise_not_configured():
        raise EmailNotConfigured("smtp is disabled in tests")

    monkeypatch.setattr("app.routes.auth._email_sender", raise_not_configured)

    response = client.post(
        "/auth/email/start-add",
        json={"email": "john_doe@example.com"},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_NOT_CONFIGURED"
    assert data["detail"]["detail"] == "smtp is disabled in tests"

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="email_add",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_email_confirm_add_success_sets_email_verifies_and_consumes_code(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": code},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "email_verified"}

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()

    assert row.consumed_at is not None
    assert row.attempts == 1
    assert updated_user.email == "john_doe@example.com"
    assert updated_user.email_verified_at is not None


def test_email_confirm_add_returns_400_when_no_pending_code(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": "123456"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "NO_PENDING_CODE"
    assert data["detail"]["detail"] == "No pending code"


def test_email_confirm_add_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="john_doe")
    auth_as(user)
    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": code},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert row.consumed_at is None
    assert row.attempts == 0
    assert updated_user.email is None
    assert updated_user.email_verified_at is None


def test_email_confirm_add_returns_400_when_code_expired(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": "123456"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "CODE_EXPIRED"
    assert data["detail"]["detail"] == "Code expired"


def test_email_confirm_add_returns_429_when_attempt_limit_reached(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=5,
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": "123456"},
    )

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_ATTEMPTS"
    assert data["detail"]["detail"] == "Too many attempts"


def test_email_confirm_add_returns_400_and_increments_attempts_on_wrong_code(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    auth_as(user)

    row, _ = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=0,
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": "654321"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "WRONG_CODE"
    assert data["detail"]["detail"] == "Wrong code"

    db_session.refresh(row)
    assert row.attempts == 1
    assert row.consumed_at is None


def test_email_confirm_add_returns_409_when_email_became_used_by_other_user(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe")
    user_factory(username="jane_doe", email="john_doe@example.com", verified=True)
    auth_as(user)

    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_add",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-add",
        json={"email": "john_doe@example.com", "code": code},
    )

    assert response.status_code == 409
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_IN_USE"
    assert data["detail"]["detail"] == "Email already in use"

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.email is None


def test_email_start_remove_success_creates_code_and_sends_message(
    client,
    db_session,
    user_factory,
    auth_as,
    fake_email_sender,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    response = client.post("/auth/email/start-remove")

    assert response.status_code == 200
    assert response.json() == {"detail": "code_sent"}

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id, purpose="email_remove", target_email="john_doe@example.com"
        )
        .all()
    )
    assert len(rows) == 1
    assert rows[0].consumed_at is None
    assert rows[0].attempts == 0

    assert len(fake_email_sender.sent) == 1
    sent = fake_email_sender.sent[0]
    assert sent["email"] == "john_doe@example.com"
    assert sent["subject"] == "Remove email from account"
    assert "Expires in: 10 minutes." in sent["text"]


def test_email_start_remove_returns_400_when_no_verified_email(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="john_doe", email=None, verified=False)
    auth_as(user)

    response = client.post("/auth/email/start-remove")

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "NO_VERIFIED_EMAIL"
    assert data["detail"]["detail"] == "No verified email"


def test_email_start_remove_returns_429_when_cooldown_is_active(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post("/auth/email/start-remove")

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_REQUESTS"
    assert data["detail"]["detail"] == "Too many requests. Try later."


def test_email_start_remove_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post("/auth/email/start-remove")

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="email_remove",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_email_start_remove_returns_503_when_sender_not_configured(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    def raise_not_configured():
        raise EmailNotConfigured("smtp remove disabled")

    monkeypatch.setattr("app.routes.auth._email_sender", raise_not_configured)

    response = client.post("/auth/email/start-remove")

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_NOT_CONFIGURED"
    assert data["detail"]["detail"] == "smtp remove disabled"

    rows = (
        db_session.query(EmailCode)
        .filter_by(
            user_id=user.id,
            purpose="email_remove",
            target_email="john_doe@example.com",
        )
        .all()
    )
    assert len(rows) == 0


def test_email_confirm_remove_by_code_success_clears_email_and_consumes_code(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": code},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "email_removed"}

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()

    assert row.consumed_at is not None
    assert row.attempts == 1
    assert updated_user.email is None
    assert updated_user.email_verified_at is None


def test_email_confirm_remove_by_code_returns_400_when_no_pending_code(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": "123456"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "NO_PENDING_CODE"
    assert data["detail"]["detail"] == "No pending code"


def test_email_confirm_remove_returns_503_when_email_disabled(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)
    row, code = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        consumed=False,
    )
    monkeypatch.setenv("EMAIL_ENABLED", "false")

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": code},
    )

    assert response.status_code == 503
    data = response.json()

    assert data["detail"]["error"] == "EMAIL_DISABLED"
    assert data["detail"]["detail"] == EMAIL_DISABLED_DETAIL

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert row.consumed_at is None
    assert row.attempts == 0
    assert updated_user.email == "john_doe@example.com"
    assert updated_user.email_verified_at is not None


def test_email_confirm_remove_by_code_returns_400_when_expired(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": "123456"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "CODE_EXPIRED"
    assert data["detail"]["detail"] == "Code expired"


def test_email_confirm_remove_by_code_returns_429_when_attempt_limit_reached(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=5,
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": "123456"},
    )

    assert response.status_code == 429
    data = response.json()

    assert data["detail"]["error"] == "TOO_MANY_ATTEMPTS"
    assert data["detail"]["detail"] == "Too many attempts"


def test_email_confirm_remove_by_code_returns_400_and_increments_attempts_on_wrong_code(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    row, _ = create_email_code(
        db_session,
        user_id=user.id,
        purpose="email_remove",
        target_email="john_doe@example.com",
        plain_code="123456",
        attempts=0,
        consumed=False,
    )

    response = client.post(
        "/auth/email/confirm-remove",
        json={"code": "654321"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "WRONG_CODE"
    assert data["detail"]["detail"] == "Wrong code"

    db_session.refresh(row)
    assert row.attempts == 1
    assert row.consumed_at is None


def test_email_confirm_remove_by_recovery_code_success_marks_code_used_and_clears_email(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    row, recovery_code = create_recovery_code(
        db_session,
        user_id=user.id,
        plain_code="ABCD-EFGH-IJKL",
        used=False,
    )

    response = client.post(
        "/auth/email/confirm-remove",
        json={"recovery_code": recovery_code},
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "email_removed"}

    db_session.refresh(row)
    updated_user = db_session.query(User).filter_by(id=user.id).first()

    assert row.used_at is not None
    assert updated_user.email is None
    assert updated_user.email_verified_at is None


def test_email_confirm_remove_by_recovery_code_returns_400_for_wrong_code(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    response = client.post(
        "/auth/email/confirm-remove",
        json={"recovery_code": "WRONG-CODE-0000"},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "WRONG_RECOVERY_CODE"
    assert data["detail"]["detail"] == "Wrong recovery code"


def test_email_confirm_remove_returns_400_when_no_code_or_recovery_code_provided(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(
        username="john_doe",
        email="john_doe@example.com",
        verified=True,
    )
    auth_as(user)

    response = client.post(
        "/auth/email/confirm-remove",
        json={},
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "MISSING_CODE"
    assert data["detail"]["detail"] == "Provide code or recovery_code"
