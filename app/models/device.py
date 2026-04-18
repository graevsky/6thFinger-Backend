import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class Device(Base):
    """
    ESP32 based prothesis
    Basic device entity.
    Stores the network address and an optional user-defined alias.
    """

    __tablename__ = "devices"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # Owner ID
    owner_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Device BLE address
    address = Column(String(64), nullable=False)

    # Optional human-readable name shown in UI
    alias = Column(String(64), nullable=True)

    # Creation timestamp.
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class DeviceSettings(Base):
    """
    Latest saved settings for a device.

    Settings are stored as JSON payload. Version is incremented on each update
    so the client can distinguish newer state from older one.
    """

    __tablename__ = "device_settings"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # Device that owns this settings record
    device_id = Column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )

    # Monotonic version of the saved settings
    version = Column(Integer, nullable=False)

    # Device JSON settings payload
    payload = Column(JSON, nullable=False)

    # Timestamp of the latest update
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )