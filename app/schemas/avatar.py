from pydantic import BaseModel, Field


class AvatarOut(BaseModel):
    """Avatar upload result returned after successful save."""

    key: str = Field(..., description="Storage key of the saved avatar object.")
    content_type: str = Field(
        ..., description="Detected MIME type of the saved avatar."
    )
