from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.schemas.device import (
    DeviceCreate,
    DeviceOut,
    DeviceSettingsIn,
    DeviceSettingsOut,
    DeviceUpdate,
)
from app.services import device_service
from app.services.common import ServiceError

router = APIRouter(prefix="/device", tags=["device"])


def _raise_service_error(exc: ServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("/", response_model=list[DeviceOut])
def list_devices(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return device_service.list_devices(db, user.id)


@router.post("/", response_model=DeviceOut)
def create_device(
    device: DeviceCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return device_service.create_device(
        db=db,
        user_id=user.id,
        address=device.address,
        alias=device.alias,
    )


@router.put("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: UUID,
    data: DeviceUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return device_service.update_device_alias(
            db=db,
            user_id=user.id,
            device_id=device_id,
            alias=data.alias,
        )
    except ServiceError as exc:
        _raise_service_error(exc)


@router.get("/{device_id}/settings", response_model=DeviceSettingsOut)
def get_settings(
    device_id: UUID,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return device_service.get_device_settings(
            db=db,
            user_id=user.id,
            device_id=device_id,
        )
    except ServiceError as exc:
        _raise_service_error(exc)


@router.post("/{device_id}/settings", response_model=DeviceSettingsOut)
def update_settings(
    device_id: UUID,
    data: DeviceSettingsIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return device_service.update_device_settings(
            db=db,
            user_id=user.id,
            device_id=device_id,
            payload=data.payload,
        )
    except ServiceError as exc:
        _raise_service_error(exc)
