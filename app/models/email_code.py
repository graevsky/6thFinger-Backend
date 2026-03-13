import uuid
from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary, String, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class EmailCode(Base):
    __tablename__ = "email_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    purpose = Column(String(64), nullable=False)

    target_email = Column(String(320), nullable=False)

    code_hash = Column(LargeBinary, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    attempts = Column(Integer, nullable=False, default=0)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
