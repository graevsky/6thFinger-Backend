from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime


class AppSettingsOut(BaseModel):
    id: UUID
    user_id: UUID
    payload: dict
    updated_at: datetime

    class Config:
        orm_mode = True


class AppSettingsIn(BaseModel):
    payload: dict = Field(..., description="usr settings json")
