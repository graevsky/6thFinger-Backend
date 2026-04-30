import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import redis_client
from app.db import Base
from app.deps import get_current_user, get_db as deps_get_db
from app.main import app
from app.middleware import official_client_gate
from app.security import client_request_signature
from app.security import rate_limit
from app.services import auth_service
from app.services import client_identity_service
from tests.factories import create_user
from tests.mocks import FakeEmailSender, FakeRedis

TEST_DATABASE_URL = "sqlite://"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


@pytest.fixture(scope="session", autouse=True)
def prepare_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def fake_redis(monkeypatch):
    original_get_redis = redis_client.get_redis
    fake_redis = FakeRedis()
    original_get_redis.cache_clear()
    monkeypatch.setattr(redis_client, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(auth_service, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(client_identity_service, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(client_request_signature, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(rate_limit, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(rate_limit, "RATE_LIMIT_ENABLED", False)
    yield fake_redis
    fake_redis.clear()
    original_get_redis.cache_clear()


@pytest.fixture(autouse=True)
def clear_runtime_state(fake_redis):
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def email_link_env(monkeypatch):
    monkeypatch.setenv("EMAIL_LANDING_URL", "https://prothesis.ru")
    monkeypatch.setenv("EMAIL_GUIDE_URL", "https://google.com")


@pytest.fixture()
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(sess, trans):
        nonlocal nested
        if not nested.is_active and connection.in_transaction():
            nested = connection.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", restart_savepoint)
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session):
    class _SessionProxy:
        def __init__(self, session):
            self._session = session

        def __getattr__(self, item):
            return getattr(self._session, item)

        def close(self):
            return None

    def override_get_db():
        yield db_session

    original_session_local = official_client_gate.SessionLocal
    app.dependency_overrides[deps_get_db] = override_get_db
    official_client_gate.SessionLocal = lambda: _SessionProxy(db_session)

    try:
        with TestClient(app, base_url="http://localhost") as test_client:
            yield test_client
    finally:
        official_client_gate.SessionLocal = original_session_local


@pytest.fixture()
def fake_email_sender(monkeypatch):
    sender = FakeEmailSender()
    monkeypatch.setattr("app.routes.auth._email_sender", lambda: sender)
    return sender


@pytest.fixture()
def user_factory(db_session):
    def factory(**kwargs):
        return create_user(db_session, **kwargs)

    return factory


@pytest.fixture()
def auth_as():
    def _auth_as(user):
        def override_current_user():
            return user

        app.dependency_overrides[get_current_user] = override_current_user
        return user

    return _auth_as
