from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import deps as deps_module
from app.deps import get_current_user
from app.security.client_request_signature import AuthenticatedClient
from app.services import auth_service
from app.services.common import ServiceError
from tests.factories import create_token


class _SuccessfulLoginSession:
    def __init__(self):
        self.key_proof_hash = b"server-proof-m2"

    def process(self, A, salt):
        self.process_called_with = (A, salt)

    def verify_proof(self, client_M1: bytes):
        return True


def _store_fake_srp_session(fake_redis, username, private="fake-private-session"):
    fake_redis.set(auth_service._srp_session_key(username), private)


def _client(
    *,
    instance_id: str = "11111111-1111-1111-1111-111111111111",
    key_id: str = "test-key-id",
    public_key_sha256: str = "a" * 64,
) -> AuthenticatedClient:
    return AuthenticatedClient(
        instance_id=instance_id,
        key_id=key_id,
        public_key_sha256=public_key_sha256,
    )


def test_finish_login_binds_tokens_to_attested_client(
    db_session,
    fake_redis,
    user_factory,
    monkeypatch,
):
    user = user_factory(username="john_doe")
    login_client = _client(public_key_sha256="b" * 64)
    fake_session = _SuccessfulLoginSession()
    captured_payloads: dict[str, dict] = {}
    fake_expire = auth_service.now_utc()

    _store_fake_srp_session(fake_redis, "john_doe")
    monkeypatch.setattr(
        auth_service,
        "_restore_srp_session",
        lambda username, verifier_hex, session_private: fake_session,
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_access_token",
        lambda payload: (
            captured_payloads.setdefault("access", payload.copy()) and "access-token",
            b"access-jti-hash",
        ),
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_refresh_token",
        lambda payload: (
            captured_payloads.setdefault("refresh", payload.copy()) and "refresh-token",
            b"refresh-hash",
            fake_expire,
        ),
    )

    result = auth_service.finish_login(
        db=db_session,
        username_raw="john_doe",
        A="client-public-A",
        M1="client-proof-m1",
        salt="0abc",
        client=login_client,
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert captured_payloads["access"]["sub"] == str(user.id)
    assert captured_payloads["refresh"]["sub"] == str(user.id)
    assert captured_payloads["access"]["cid"] == login_client.instance_id
    assert captured_payloads["refresh"]["cid"] == login_client.instance_id
    assert captured_payloads["access"]["cnf"]["jkt"] == login_client.public_key_sha256
    assert captured_payloads["refresh"]["cnf"]["jkt"] == login_client.public_key_sha256


def test_refresh_access_token_rejects_token_bound_to_another_client(
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(username="refresh_user")
    _, refresh_token = create_token(
        db_session,
        user_id=user.id,
        refresh_token="good-refresh-token",
    )
    refresh_client = _client()

    monkeypatch.setattr(
        auth_service.tokens,
        "verify_token",
        lambda token: {
            "sub": str(user.id),
            "typ": "refresh",
            "cid": "22222222-2222-2222-2222-222222222222",
            "cnf": {"jkt": "c" * 64},
        },
    )

    with pytest.raises(ServiceError) as exc:
        auth_service.refresh_access_token(
            db_session,
            refresh_token,
            client=refresh_client,
        )

    assert exc.value.status_code == 401
    assert exc.value.detail["error"] == "INVALID_CLIENT_BINDING"


def test_refresh_access_token_preserves_client_binding(
    db_session,
    user_factory,
    monkeypatch,
):
    user = user_factory(username="refresh_user")
    _, refresh_token = create_token(
        db_session,
        user_id=user.id,
        refresh_token="good-refresh-token",
    )
    refresh_client = _client(public_key_sha256="d" * 64)
    captured_payload = {}

    monkeypatch.setattr(
        auth_service.tokens,
        "verify_token",
        lambda token: {
            "sub": str(user.id),
            "typ": "refresh",
            "cid": refresh_client.instance_id,
            "cnf": {"jkt": refresh_client.public_key_sha256},
        },
    )
    monkeypatch.setattr(
        auth_service.tokens,
        "create_access_token",
        lambda payload: (
            captured_payload.setdefault("value", payload.copy()) and "new-access-token",
            b"new-access-jti-hash",
        ),
    )

    result = auth_service.refresh_access_token(
        db_session,
        refresh_token,
        client=refresh_client,
    )

    assert result == {"access_token": "new-access-token"}
    assert captured_payload["value"]["sub"] == str(user.id)
    assert captured_payload["value"]["cid"] == refresh_client.instance_id
    assert captured_payload["value"]["cnf"]["jkt"] == refresh_client.public_key_sha256


def test_get_current_user_rejects_invalid_client_binding_when_attestation_enabled(
    db_session,
    user_factory,
    monkeypatch,
):
    monkeypatch.setenv("CLIENT_ATTESTATION_ENABLED", "true")
    user = user_factory(username="binding_user")
    create_token(
        db_session,
        user_id=user.id,
        access_token="access-jti-123",
        refresh_token="refresh-token",
    )

    request = SimpleNamespace(state=SimpleNamespace(client_instance=_client()))
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="fake.jwt.token",
    )
    monkeypatch.setattr(
        deps_module.tokens,
        "verify_token",
        lambda token: {
            "sub": user.id,
            "typ": "access",
            "jti": "access-jti-123",
            "cid": "99999999-9999-9999-9999-999999999999",
            "cnf": {"jkt": "f" * 64},
        },
    )

    with pytest.raises(HTTPException) as exc:
        get_current_user(request, credentials, db_session)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid client binding"


def test_get_current_user_accepts_matching_client_binding(
    db_session,
    user_factory,
    monkeypatch,
):
    monkeypatch.setenv("CLIENT_ATTESTATION_ENABLED", "true")
    user = user_factory(username="binding_user")
    bound_client = _client(public_key_sha256="e" * 64)
    create_token(
        db_session,
        user_id=user.id,
        access_token="access-jti-456",
        refresh_token="refresh-token",
    )

    request = SimpleNamespace(state=SimpleNamespace(client_instance=bound_client))
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="fake.jwt.token",
    )
    monkeypatch.setattr(
        deps_module.tokens,
        "verify_token",
        lambda token: {
            "sub": user.id,
            "typ": "access",
            "jti": "access-jti-456",
            "cid": bound_client.instance_id,
            "cnf": {"jkt": bound_client.public_key_sha256},
        },
    )

    result = get_current_user(request, credentials, db_session)

    assert result.id == user.id
