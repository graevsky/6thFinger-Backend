from pydantic import BaseModel, Field
from uuid import UUID
from typing import Optional
from datetime import datetime


class DeviceCreate(BaseModel):
    address: str
    alias: Optional[str] = None


class DeviceUpdate(BaseModel):
    alias: Optional[str] = None


class DeviceOut(BaseModel):
    id: UUID
    owner_id: UUID
    address: str
    alias: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


class DeviceSettingsOut(BaseModel):
    id: UUID
    device_id: UUID
    version: int
    payload: dict
    updated_at: datetime

    class Config:
        orm_mode = True


class DeviceSettingsIn(BaseModel):
    payload: dict = Field(..., description="device settings json")
