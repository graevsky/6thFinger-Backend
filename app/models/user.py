from sqlalchemy import Column, String, Boolean, LargeBinary, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    username = Column(String(32), unique=True, nullable=False)
    srp_salt = Column(LargeBinary, nullable=False)
    srp_verifier = Column(LargeBinary, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    avatar_key = Column(String(265), nullable=True)
    email = Column(String(320), unique=True, nullable=True)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
