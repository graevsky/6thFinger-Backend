from uuid import UUID

from sqlalchemy.orm import Session

from app.models.device import Device, DeviceSettings
from app.services.common import ServiceError, now_utc


def list_devices(db: Session, user_id) -> list[Device]:
    return db.query(Device).filter_by(owner_id=user_id).all()


def create_device(db: Session, user_id, address: str, alias: str | None) -> Device:
    device = Device(owner_id=user_id, address=address, alias=alias)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def update_device_alias(
    db: Session, user_id, device_id: UUID, alias: str | None
) -> Device:
    device = db.query(Device).filter_by(id=device_id, owner_id=user_id).first()
    if not device:
        raise ServiceError(status_code=404, detail="Device not found")

    device.alias = alias
    db.commit()
    db.refresh(device)
    return device


def get_device_settings(db: Session, user_id, device_id: UUID) -> DeviceSettings:
    device = db.query(Device).filter_by(id=device_id, owner_id=user_id).first()
    if not device:
        raise ServiceError(status_code=404, detail="Device not found")

    settings = (
        db.query(DeviceSettings)
        .filter_by(device_id=device_id)
        .order_by(DeviceSettings.updated_at.desc())
        .first()
    )
    if not settings:
        raise ServiceError(status_code=404, detail="Settings not found")

    return settings


def update_device_settings(
    db: Session,
    user_id,
    device_id: UUID,
    payload: dict,
) -> DeviceSettings:
    device = db.query(Device).filter_by(id=device_id, owner_id=user_id).first()
    if not device:
        raise ServiceError(status_code=404, detail="Device not found")

    now = now_utc()

    settings = (
        db.query(DeviceSettings)
        .filter_by(device_id=device.id)
        .order_by(DeviceSettings.updated_at.desc())
        .first()
    )

    if settings:
        settings.version = (settings.version or 0) + 1
        settings.payload = payload
        settings.updated_at = now
    else:
        settings = DeviceSettings(
            device_id=device.id,
            version=1,
            payload=payload,
            updated_at=now,
        )
        db.add(settings)

    db.commit()
    db.refresh(settings)
    return settings
