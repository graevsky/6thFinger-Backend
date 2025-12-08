import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID

from app.db import SessionLocal
from app.deps import get_current_user
from app.models.device import Device, DeviceSettings
from app.schemas.device import (
    DeviceCreate,
    DeviceOut,
    DeviceSettingsIn,
    DeviceSettingsOut,
    DeviceUpdate,
)


router = APIRouter(prefix="/device", tags=["device"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/", response_model=list[DeviceOut])
def list_devices(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Device).filter_by(owner_id=user.id).all()


@router.post("/", response_model=DeviceOut)
def create_device(
    device: DeviceCreate, user=Depends(get_current_user), db: Session = Depends(get_db)
):
    dev = Device(owner_id=user.id, address=device.address, alias=device.alias)
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return dev


@router.put("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: UUID,
    data: DeviceUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter_by(id=device_id, owner_id=user.id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.alias = data.alias
    db.commit()
    db.refresh(device)
    return device


@router.get("/{device_id}/settings", response_model=DeviceSettingsOut)
def get_settings(
    device_id: UUID, user=Depends(get_current_user), db: Session = Depends(get_db)
):
    device = db.query(Device).filter_by(id=device_id, owner_id=user.id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    settings = (
        db.query(DeviceSettings)
        .filter_by(device_id=device_id)
        .order_by(DeviceSettings.updated_at.desc())
        .first()
    )
    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")
    return settings


@router.post("/{device_id}/settings", response_model=DeviceSettingsOut)
def update_settings(
    device_id: UUID,
    data: DeviceSettingsIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter_by(id=device_id, owner_id=user.id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    now = datetime.datetime.now(datetime.timezone.utc)

    settings = (
        db.query(DeviceSettings)
        .filter_by(device_id=device.id)
        .order_by(DeviceSettings.updated_at.desc())
        .first()
    )

    if settings:
        settings.version = (settings.version or 0) + 1
        settings.payload = data.payload
        settings.updated_at = now
    else:
        settings = DeviceSettings(
            device_id=device.id,
            version=1,
            payload=data.payload,
            updated_at=now,
        )
        db.add(settings)

    db.commit()
    db.refresh(settings)
    return settings
