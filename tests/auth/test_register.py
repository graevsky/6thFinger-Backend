import re

from app.models.recovery_code import RecoveryCode
from app.models.user import User


def test_get_srp_params_returns_N_and_g(client):
    response = client.get("/auth/params")

    assert response.status_code == 200
    data = response.json()
    assert "N" in data
    assert "g" in data
    assert isinstance(data["N"], str)
    assert isinstance(data["g"], str)
    assert data["N"]
    assert data["g"]


def test_register_success_creates_user_and_10_recovery_codes(client, db_session):
    response = client.post(
        "/auth/register",
        json={
            "username": "  John_Doe  ",
            "salt": "0abc",
            "verifier": "abcd1234",
        },
    )

    assert response.status_code == 201
    data = response.json()

    assert data["detail"] == "registered"
    assert len(data["recovery_codes"]) == 10

    pattern = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
    assert all(pattern.fullmatch(code) for code in data["recovery_codes"])

    user = db_session.query(User).filter_by(username="john_doe").first()
    assert user is not None
    assert user.srp_salt == bytes.fromhex("0abc")
    assert user.srp_verifier == bytes.fromhex("abcd1234")

    recovery_rows = db_session.query(RecoveryCode).filter_by(user_id=user.id).all()
    assert len(recovery_rows) == 10


def test_register_duplicate_username_returns_409(client, user_factory):
    user_factory(username="John_Doe")

    response = client.post(
        "/auth/register",
        json={
            "username": "  John_Doe  ",
            "salt": "0abc",
            "verifier": "abcd1234",
        },
    )

    assert response.status_code == 409
    data = response.json()

    assert data["detail"]["error"] == "USERNAME_TAKEN"
    assert data["detail"]["detail"] == "Username already exists"


def test_register_bad_salt_returns_400_and_user_is_not_created(client, db_session):
    response = client.post(
        "/auth/register",
        json={
            "username": "jane_doe",
            "salt": "not-hex",
            "verifier": "abcd1234",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "BAD_HEX"
    assert data["detail"]["detail"] == "salt must be hex"

    user = db_session.query(User).filter_by(username="jane_doe").first()
    assert user is None


def test_register_bad_verifier_returns_400_and_user_is_not_created(client, db_session):
    response = client.post(
        "/auth/register",
        json={
            "username": "ULLI",
            "salt": "0abc",
            "verifier": "not-hex",
        },
    )

    assert response.status_code == 400
    data = response.json()

    assert data["detail"]["error"] == "BAD_HEX"
    assert data["detail"]["detail"] == "verifier must be hex"

    user = db_session.query(User).filter_by(username="ULLI").first()
    assert user is None
