import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.deps import get_current_user, get_db as deps_get_db
from app.main import app
from app.services import auth_service
from tests.factories import create_user
from tests.mocks import FakeEmailSender

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
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def clear_runtime_state():
    auth_service.active_sessions.clear()
    app.dependency_overrides.clear()
    yield
    auth_service.active_sessions.clear()
    app.dependency_overrides.clear()


@pytest.fixture()
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[deps_get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client


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
