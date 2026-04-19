import uuid

from sqlalchemy import Column, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class AppSettings(Base):
    """
    Per-user application settings.
    """

    __tablename__ = "app_settings"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # User that owns the settings
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Arbitrary settings payload
    payload = Column(JSON, nullable=False)

    # Auto-updated modification timestamp
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )