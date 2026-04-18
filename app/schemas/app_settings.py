from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime


class AppSettingsOut(BaseModel):
    """Mobile app settings stored for the current user."""

    id: UUID = Field(..., description="Settings record id.")
    user_id: UUID = Field(..., description="Id of the user these settings belong to.")
    payload: dict = Field(..., description="User settings JSON payload.")
    updated_at: datetime = Field(
        ..., description="Timestamp of the last settings update."
    )

    class Config:
        orm_mode = True


class AppSettingsIn(BaseModel):
    """Payload used to update mobile app settings."""

    payload: dict = Field(..., description="User settings JSON payload.")
