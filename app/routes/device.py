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


def _raise_service_error(exc: ServiceError) -> None:
    """Convert service-layer error into FastAPI HTTPException."""
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get(
    "/",
    response_model=list[DeviceOut],
    summary="List user devices",
)
def list_devices(user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Return all devices that belong to the current user."""
    return device_service.list_devices(db, user.id)


@router.post(
    "/",
    response_model=DeviceOut,
    summary="Create device",
)
def create_device(
    device: DeviceCreate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new device bound to the user."""
    return device_service.create_device(
        db=db,
        user_id=user.id,
        address=device.address,
        alias=device.alias,
    )


@router.put(
    "/{device_id}",
    response_model=DeviceOut,
    summary="Update device alias",
)
def update_device(
    device_id: UUID,
    data: DeviceUpdate,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update UI alias of an owned device."""
    try:
        return device_service.update_device_alias(
            db=db,
            user_id=user.id,
            device_id=device_id,
            alias=data.alias,
        )
    except ServiceError as exc:
        _raise_service_error(exc)


@router.get(
    "/{device_id}/settings",
    response_model=DeviceSettingsOut,
    summary="Get device settings",
)
def get_settings(
    device_id: UUID,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the latest saved settings for a device."""
    try:
        return device_service.get_device_settings(
            db=db,
            user_id=user.id,
            device_id=device_id,
        )
    except ServiceError as exc:
        _raise_service_error(exc)


@router.post(
    "/{device_id}/settings",
    response_model=DeviceSettingsOut,
    summary="Update device settings",
)
def update_settings(
    device_id: UUID,
    data: DeviceSettingsIn,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Save new device settings payload.
    For existing settings, increments version by 1.
    """
    try:
        return device_service.update_device_settings(
            db=db,
            user_id=user.id,
            device_id=device_id,
            payload=data.payload,
        )
    except ServiceError as exc:
        _raise_service_error(exc)
