import datetime as dt
import uuid

from app.models.token import Token
from app.services import auth_service
from tests.factories import create_token


class FakeStartServerSession:
    def __init__(self, ctx, verifier_hex):
        self.ctx = ctx
        self.verifier_hex = verifier_hex
        self.public = "fake-server-public-B"
        self.private = "fake-private-session"


class FakeSuccessfulLoginSession:
    def __init__(self):
        self.process_called_with = None
        self.key_proof_hash = b"server-proof-m2"

    def process(self, A, salt):
        self.process_called_with = (A, salt)

    def verify_proof(self, client_M1: bytes):
        return True


class FakeWrongPasswordSession:
    def process(self, A, salt):
        self.process_called_with = (A, salt)

    def verify_proof(self, client_M1: bytes):
        return False


class FakeExplodingSession:
    def process(self, A, salt):
        raise ValueError("boom")

    def verify_proof(self, client_M1: bytes):
        return True


def _store_fake_srp_session(fake_redis, username, private="fake-private-session"):
    fake_redis.set(auth_service._srp_session_key(username), private)


def test_login_start_success_returns_srp_data_and_stores_active_session(
    client,
    fake_redis,
    user_factory,
    monkeypatch,
):
    user_factory(
        username="john_doe",
        srp_salt=bytes.fromhex("0abc"),
        srp_verifier=bytes.fromhex("abcd1234"),
    )

    monkeypatch.setattr(auth_service, "SRPServerSession", FakeStartServerSession)

    response = client.post(
        "/auth/login/start",
        json={"username": "  john_doe  "},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["salt"] == "0abc"
    assert data["B"] == "fake-server-public-B"
    assert "N" in data
    assert "g" in data

    assert (
        fake_redis.get(auth_service._srp_session_key("john_doe"))
        == "fake-private-session"
    )


def test_login_start_user_not_found_returns_404(client):
    response = client.post(
        "/auth/login/start",
        json={"username": "missing_user"},
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_login_finish_success_returns_tokens_and_persists_refresh_hash(
    client,
    db_session,
    fake_redis,
    user_factory,
    monkeypatch,
):
    user = user_factory(username="john_doe")
    fake_session = FakeSuccessfulLoginSession()
    _store_fake_srp_session(fake_redis, "john_doe")

    fake_expire = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)

    monkeypatch.setattr(
        auth_service,
        "_restore_srp_session",
        lambda username, verifier_hex, session_private: fake_session,
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_access_token",
        lambda payload: ("access-token-123", b"access-jti-hash-123"),
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_refresh_token",
        lambda payload: ("refresh-token-456", b"refresh-hash-456", fake_expire),
    )

    response = client.post(
        "/auth/login/finish",
        json={
            "username": "  john_doe  ",
            "A": "client-public-A",
            "M1": "client-proof-m1",
            "salt": "0abc",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["M2"] == "server-proof-m2"
    assert data["access_token"] == "access-token-123"
    assert data["refresh_token"] == "refresh-token-456"

    token_row = db_session.query(Token).filter_by(user_id=user.id).first()
    assert token_row is not None
    assert token_row.access_jti_hash == b"access-jti-hash-123"
    assert token_row.token_hash == b"refresh-hash-456"
    assert token_row.expires_at is not None
    assert token_row.expires_at.replace(tzinfo=dt.timezone.utc) == fake_expire
    assert token_row.last_used_at is not None

    assert fake_session.process_called_with == ("client-public-A", "0abc")
    assert fake_redis.get(auth_service._srp_session_key("john_doe")) is None


def test_login_finish_returns_400_when_no_active_session(client):
    response = client.post(
        "/auth/login/finish",
        json={
            "username": "john_doe",
            "A": "client-public-A",
            "M1": "client-proof-m1",
            "salt": "0abc",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "NO_ACTIVE_SESSION"
    assert data["detail"]["detail"] == "No active session"


def test_login_finish_returns_401_when_proof_is_wrong(
    client,
    fake_redis,
    user_factory,
    monkeypatch,
):
    user_factory(username="john_doe")
    _store_fake_srp_session(fake_redis, "john_doe")
    monkeypatch.setattr(
        auth_service,
        "_restore_srp_session",
        lambda username, verifier_hex, session_private: FakeWrongPasswordSession(),
    )

    response = client.post(
        "/auth/login/finish",
        json={
            "username": "john_doe",
            "A": "client-public-A",
            "M1": "client-proof-m1",
            "salt": "0abc",
        },
    )

    assert response.status_code == 401
    data = response.json()

    assert data["detail"]["error"] == "WRONG_PASSWORD"
    assert data["detail"]["detail"] == "Invalid username or password"


def test_login_finish_returns_401_when_session_process_raises(
    client,
    fake_redis,
    user_factory,
    monkeypatch,
):
    user_factory(username="john_doe")
    _store_fake_srp_session(fake_redis, "john_doe")
    monkeypatch.setattr(
        auth_service,
        "_restore_srp_session",
        lambda username, verifier_hex, session_private: FakeExplodingSession(),
    )

    response = client.post(
        "/auth/login/finish",
        json={
            "username": "john_doe",
            "A": "client-public-A",
            "M1": "client-proof-m1",
            "salt": "0abc",
        },
    )

    assert response.status_code == 401
    data = response.json()

    assert data["detail"]["error"] == "WRONG_PASSWORD"
    assert data["detail"]["detail"] == "Invalid username or password"


def test_login_finish_returns_404_when_user_not_found_after_session_exists(
    client,
    fake_redis,
):
    _store_fake_srp_session(fake_redis, "ghost")

    response = client.post(
        "/auth/login/finish",
        json={
            "username": "ghost",
            "A": "client-public-A",
            "M1": "client-proof-m1",
            "salt": "0abc",
        },
    )

    assert response.status_code == 404
    data = response.json()

    assert data["detail"]["error"] == "USER_NOT_FOUND"
    assert data["detail"]["detail"] == "User not found"


def test_refresh_returns_400_when_token_missing(client):
    response = client.post("/auth/refresh", json={})

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "MISSING_TOKEN"
    assert data["detail"]["detail"] == "Missing token"


def test_refresh_returns_401_when_verify_token_returns_empty_payload(
    client,
    monkeypatch,
):
    monkeypatch.setattr(auth_service.tokens, "verify_token", lambda token: {})

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": "bad-token"},
    )

    assert response.status_code == 401
    data = response.json()

    assert data["detail"]["error"] == "INVALID_REFRESH"
    assert data["detail"]["detail"] == "Invalid refresh token"


def test_refresh_returns_401_when_token_type_is_not_refresh(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        auth_service.tokens,
        "verify_token",
        lambda token: {"sub": str(uuid.uuid4()), "typ": "access"},
    )

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": "wrong-type-token"},
    )

    assert response.status_code == 401
    data = response.json()

    assert data["detail"]["error"] == "INVALID_REFRESH"
    assert data["detail"]["detail"] == "Invalid refresh token"


def test_refresh_returns_401_when_token_is_not_found_in_db(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        auth_service.tokens,
        "verify_token",
        lambda token: {"sub": str(uuid.uuid4()), "typ": "refresh"},
    )

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": "missing-db-token"},
    )

    assert response.status_code == 401
    data = response.json()

    assert data["detail"]["error"] == "TOKEN_REVOKED"
    assert data["detail"]["detail"] == "Token revoked or missing"


def test_refresh_success_returns_new_access_token_and_updates_db_row(
    client,
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(username="refresh_user")
    token_row, refresh_token = create_token(
        db_session,
        user_id=user.id,
        access_token="old-access-token",
        refresh_token="good-refresh-token",
        revoked=False,
    )

    monkeypatch.setattr(
        auth_service.tokens,
        "verify_token",
        lambda token: {"sub": str(user.id), "typ": "refresh"},
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_access_token",
        lambda payload: ("new-access-token", b"new-access-jti-hash"),
    )

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    assert response.json() == {"access_token": "new-access-token"}

    db_session.refresh(token_row)
    assert token_row.access_jti_hash == b"new-access-jti-hash"
    assert token_row.last_used_at is not None


def test_logout_revokes_all_active_user_tokens(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="logout_user")
    auth_as(user)

    active_1, _ = create_token(
        db_session,
        user_id=user.id,
        access_token="access-1",
        refresh_token="refresh-1",
        revoked=False,
    )
    active_2, _ = create_token(
        db_session,
        user_id=user.id,
        access_token="access-2",
        refresh_token="refresh-2",
        revoked=False,
    )
    revoked_already, _ = create_token(
        db_session,
        user_id=user.id,
        access_token="access-3",
        refresh_token="refresh-3",
        revoked=True,
    )

    response = client.post("/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"detail": "logged out"}

    db_session.refresh(active_1)
    db_session.refresh(active_2)
    db_session.refresh(revoked_already)

    assert active_1.revoked_at is not None
    assert active_2.revoked_at is not None
    assert active_1.last_used_at is not None
    assert active_2.last_used_at is not None
    assert revoked_already.revoked_at is not None


def test_me_returns_current_user_data(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="me_user")
    auth_as(user)

    response = client.get("/auth/me")

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(user.id)
    assert data["username"] == "me_user"
