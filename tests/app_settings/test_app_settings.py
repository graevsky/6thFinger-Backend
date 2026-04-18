import datetime as dt

from app.models.app_settings import AppSettings
from tests.factories import create_app_settings


def test_get_settings_creates_default_settings_when_absent(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_1")
    auth_as(user)

    response = client.get("/settings/")

    assert response.status_code == 200
    data = response.json()

    assert data["user_id"] == str(user.id)
    assert data["payload"] == {"language": "en"}
    assert data["id"]

    row = db_session.query(AppSettings).filter_by(user_id=user.id).first()
    assert row is not None
    assert row.payload == {"language": "en"}


def test_get_settings_returns_existing_settings_without_changes_when_language_exists(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_2")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"language": "ru", "theme": "dark"},
    )
    old_updated_at = row.updated_at

    response = client.get("/settings/")

    assert response.status_code == 200
    data = response.json()

    assert data["user_id"] == str(user.id)
    assert data["payload"] == {"language": "ru", "theme": "dark"}

    db_session.refresh(row)
    assert row.payload == {"language": "ru", "theme": "dark"}
    assert row.updated_at == old_updated_at


def test_get_settings_adds_default_language_when_missing(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_3")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"theme": "dark"},
    )

    response = client.get("/settings/")

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {"theme": "dark", "language": "en"}

    db_session.refresh(row)
    assert row.payload == {"theme": "dark", "language": "en"}
    assert row.updated_at is not None


def test_update_settings_creates_new_settings_with_default_language_when_absent(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_4")
    auth_as(user)

    response = client.put(
        "/settings/",
        json={"payload": {"theme": "dark"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["user_id"] == str(user.id)
    assert data["payload"] == {"language": "en", "theme": "dark"}

    row = db_session.query(AppSettings).filter_by(user_id=user.id).first()
    assert row is not None
    assert row.payload == {"language": "en", "theme": "dark"}


def test_update_settings_creates_new_settings_and_normalizes_language(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_5")
    auth_as(user)

    response = client.put(
        "/settings/",
        json={"payload": {"language": "RU", "theme": "dark"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {"language": "ru", "theme": "dark"}

    row = db_session.query(AppSettings).filter_by(user_id=user.id).first()
    assert row is not None
    assert row.payload == {"language": "ru", "theme": "dark"}


def test_update_settings_existing_merges_payload_and_preserves_existing_keys(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_6")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"language": "en", "theme": "dark", "volume": 10},
    )

    response = client.put(
        "/settings/",
        json={"payload": {"theme": "light"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {
        "language": "en",
        "theme": "light",
        "volume": 10,
    }

    db_session.refresh(row)
    assert row.payload == {
        "language": "en",
        "theme": "light",
        "volume": 10,
    }


def test_update_settings_existing_normalizes_language_and_updates_value(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_7")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"language": "en", "theme": "dark"},
    )

    response = client.put(
        "/settings/",
        json={"payload": {"language": "RU"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {"language": "ru", "theme": "dark"}

    db_session.refresh(row)
    assert row.payload == {"language": "ru", "theme": "dark"}


def test_update_settings_existing_sets_default_language_when_current_payload_has_no_language(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_8")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"theme": "dark"},
    )

    response = client.put(
        "/settings/",
        json={"payload": {"volume": 7}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {
        "theme": "dark",
        "volume": 7,
        "language": "en",
    }

    db_session.refresh(row)
    assert row.payload == {
        "theme": "dark",
        "volume": 7,
        "language": "en",
    }


def test_update_settings_invalid_language_falls_back_to_en(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_9")
    auth_as(user)

    response = client.put(
        "/settings/",
        json={"payload": {"language": "de"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {"language": "en"}

    row = db_session.query(AppSettings).filter_by(user_id=user.id).first()
    assert row is not None
    assert row.payload == {"language": "en"}


def test_update_settings_overwrites_language_alias_only_if_sent_as_language(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="settings_user_10")
    auth_as(user)

    row = create_app_settings(
        db_session,
        user.id,
        payload={"language": "en", "theme": "dark"},
    )

    response = client.put(
        "/settings/",
        json={"payload": {"language": "EN", "theme": "light"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["payload"] == {"language": "en", "theme": "light"}

    db_session.refresh(row)
    assert row.payload == {"language": "en", "theme": "light"}
