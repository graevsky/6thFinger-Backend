import datetime as dt
import uuid

from app.models.device import Device, DeviceSettings


def create_device_row(
    db_session,
    owner_id,
    address="1122334455",
    alias="device_1",
):
    row = Device(
        owner_id=owner_id,
        address=address,
        alias=alias,
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)
    return row


def create_device_settings_row(
    db_session,
    device_id,
    version=1,
    payload=None,
    updated_at=None,
):
    row = DeviceSettings(
        device_id=device_id,
        version=version,
        payload=payload or {"mode": "auto"},
        updated_at=updated_at or dt.datetime(2024, 1, 1, 12, 0, 0),
    )
    db_session.add(row)
    db_session.commit()
    db_session.refresh(row)
    return row


def test_list_devices_returns_only_current_user_devices(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_1")
    other = user_factory(username="device_user_2")
    auth_as(user)

    own_1 = create_device_row(
        db_session,
        owner_id=user.id,
        address="11225",
        alias="device_2",
    )
    own_2 = create_device_row(
        db_session,
        owner_id=user.id,
        address="1122334455",
        alias="device_3",
    )
    create_device_row(
        db_session,
        owner_id=other.id,
        address="1122334455",
        alias="Other device",
    )

    response = client.get("/device/")

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 2
    returned_ids = {item["id"] for item in data}
    assert returned_ids == {str(own_1.id), str(own_2.id)}
    assert {item["address"] for item in data} == {"11225", "1122334455"}


def test_create_device_creates_new_device_for_current_user(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_3")
    auth_as(user)

    response = client.post(
        "/device/",
        json={
            "address": "1122334455",
            "alias": "esp32",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["owner_id"] == str(user.id)
    assert data["address"] == "1122334455"
    assert data["alias"] == "esp32"
    assert data["id"]

    row = db_session.query(Device).filter_by(id=uuid.UUID(data["id"])).first()
    assert row is not None
    assert row.owner_id == user.id
    assert row.address == "1122334455"
    assert row.alias == "esp32"


def test_update_device_updates_alias_for_owned_device(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_4")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
        address="1122334455",
        alias="old device",
    )

    response = client.put(
        f"/device/{device.id}",
        json={"alias": "new device"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(device.id)
    assert data["alias"] == "new device"
    assert data["address"] == "1122334455"

    db_session.refresh(device)
    assert device.alias == "new device"


def test_delete_device_removes_owned_device_and_settings(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_5")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
        address="1122334455",
        alias="delete me",
    )
    create_device_settings_row(
        db_session,
        device_id=device.id,
        version=2,
        payload={"settings": "gpio-delete"},
    )

    response = client.delete(f"/device/{device.id}")

    assert response.status_code == 200
    assert response.json() == {"detail": "device_deleted"}
    assert db_session.query(Device).filter_by(id=device.id).first() is None
    assert db_session.query(DeviceSettings).filter_by(device_id=device.id).count() == 0


def test_delete_device_returns_404_when_device_not_found(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_6")
    auth_as(user)

    missing_id = "33333333-3333-3333-3333-333333333333"

    response = client.delete(f"/device/{missing_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Device not found"}


def test_get_device_settings_returns_404_when_device_not_found(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_7")
    auth_as(user)

    missing_id = "11111111-1111-1111-1111-111111111111"

    response = client.get(f"/device/{missing_id}/settings")

    assert response.status_code == 404
    assert response.json() == {"detail": "Device not found"}


def test_get_device_settings_returns_404_when_settings_not_found(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_8")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    response = client.get(f"/device/{device.id}/settings")

    assert response.status_code == 404
    assert response.json() == {"detail": "Settings not found"}


def test_get_device_settings_returns_latest_settings_row(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_9")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    create_device_settings_row(
        db_session,
        device_id=device.id,
        version=1,
        payload={"settings": "gpio1"},
        updated_at=dt.datetime(2024, 1, 1, 10, 0, 0),
    )
    latest = create_device_settings_row(
        db_session,
        device_id=device.id,
        version=2,
        payload={"settings": "gpio2"},
        updated_at=dt.datetime(2024, 1, 1, 12, 0, 0),
    )

    response = client.get(f"/device/{device.id}/settings")

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(latest.id)
    assert data["device_id"] == str(device.id)
    assert data["version"] == 2
    assert data["payload"] == {"settings": "gpio2"}


def test_update_device_settings_returns_404_when_device_not_found(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_10")
    auth_as(user)

    missing_id = "22222222-2222-2222-2222-222222222222"

    response = client.post(
        f"/device/{missing_id}/settings",
        json={"payload": {"settings": "gpio3"}},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Device not found"}


def test_update_device_settings_creates_first_settings_row_with_version_1(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_11")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    response = client.post(
        f"/device/{device.id}/settings",
        json={"payload": {"settings": "gpio3"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["device_id"] == str(device.id)
    assert data["version"] == 1
    assert data["payload"] == {"settings": "gpio3"}

    rows = db_session.query(DeviceSettings).filter_by(device_id=device.id).all()
    assert len(rows) == 1
    assert rows[0].version == 1
    assert rows[0].payload == {"settings": "gpio3"}


def test_update_device_settings_updates_existing_latest_row_and_increments_version(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_12")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    existing = create_device_settings_row(
        db_session,
        device_id=device.id,
        version=3,
        payload={"settings": "gpio1"},
        updated_at=dt.datetime(2024, 1, 1, 12, 0, 0),
    )

    response = client.post(
        f"/device/{device.id}/settings",
        json={"payload": {"settings": "gpio2"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(existing.id)
    assert data["device_id"] == str(device.id)
    assert data["version"] == 4
    assert data["payload"] == {"settings": "gpio2"}

    db_session.refresh(existing)
    assert existing.version == 4
    assert existing.payload == {"settings": "gpio2"}


def test_update_device_settings_uses_latest_row_when_multiple_exist(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_13")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    older = create_device_settings_row(
        db_session,
        device_id=device.id,
        version=1,
        payload={"settings": "gpio1"},
        updated_at=dt.datetime(2024, 1, 1, 9, 0, 0),
    )
    latest = create_device_settings_row(
        db_session,
        device_id=device.id,
        version=5,
        payload={"settings": "gpio2"},
        updated_at=dt.datetime(2024, 1, 1, 15, 0, 0),
    )

    response = client.post(
        f"/device/{device.id}/settings",
        json={"payload": {"settings": "gpio3"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(latest.id)
    assert data["version"] == 6
    assert data["payload"] == {"settings": "gpio3"}

    db_session.refresh(older)
    db_session.refresh(latest)

    assert older.version == 1
    assert older.payload == {"settings": "gpio1"}

    assert latest.version == 6
    assert latest.payload == {"settings": "gpio3"}


def test_update_device_settings_keeps_version_when_payload_is_unchanged(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_14")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    existing = create_device_settings_row(
        db_session,
        device_id=device.id,
        version=4,
        payload={"settings": "gpio2"},
        updated_at=dt.datetime(2024, 1, 1, 12, 0, 0),
    )

    response = client.post(
        f"/device/{device.id}/settings",
        json={"payload": {"settings": "gpio2"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(existing.id)
    assert data["device_id"] == str(device.id)
    assert data["version"] == 4
    assert data["payload"] == {"settings": "gpio2"}

    db_session.refresh(existing)
    assert existing.version == 4
    assert existing.payload == {"settings": "gpio2"}
    assert existing.updated_at == dt.datetime(2024, 1, 1, 12, 0, 0)


def test_update_device_settings_accepts_legacy_string_version(
    client,
    db_session,
    user_factory,
    auth_as,
):
    user = user_factory(username="device_user_15")
    auth_as(user)

    device = create_device_row(
        db_session,
        owner_id=user.id,
    )

    create_device_settings_row(
        db_session,
        device_id=device.id,
        version="7",
        payload={"settings": "gpio7"},
        updated_at=dt.datetime(2024, 1, 1, 12, 0, 0),
    )

    response = client.post(
        f"/device/{device.id}/settings",
        json={"payload": {"settings": "gpio8"}},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["device_id"] == str(device.id)
    assert data["version"] == 8
    assert data["payload"] == {"settings": "gpio8"}
