from pydantic import BaseModel, Field
from uuid import UUID
from typing import Optional
from datetime import datetime


class DeviceCreate(BaseModel):
    """Payload for creating a new device for current user."""

    address: str = Field(..., description="Device address.")
    alias: Optional[str] = Field(None, description="Optional readable device name.")


class DeviceUpdate(BaseModel):
    """Payload for updating mutable device fields."""

    alias: Optional[str] = Field(None, description="New readable device name.")


class DeviceOut(BaseModel):
    """Device object returned by API endpoints."""

    id: UUID = Field(..., description="Device id.")
    owner_id: UUID = Field(..., description="Id of the user who owns the device.")
    address: str = Field(..., description="Device address.")
    alias: Optional[str] = Field(None, description="Optional readable device name.")
    created_at: datetime = Field(..., description="Timestamp of device creation.")

    class Config:
        orm_mode = True


class DeviceSettingsOut(BaseModel):
    """Latest stored settings snapshot for a device."""

    id: UUID = Field(..., description="Settings record id.")
    device_id: UUID = Field(
        ..., description="id of the device these settings belong to."
    )
    version: int = Field(..., description="Monotonic settings version number.")
    payload: dict = Field(..., description="Device settings JSON payload.")
    updated_at: datetime = Field(
        ..., description="Timestamp of the last settings update."
    )

    class Config:
        orm_mode = True


class DeviceSettingsIn(BaseModel):
    """Payload used to create or update device settings."""

    payload: dict = Field(..., description="Device settings JSON payload.")
