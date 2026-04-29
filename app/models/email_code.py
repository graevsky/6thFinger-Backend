import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class EmailCode(Base):
    """
    Hash of a one-time verification code sent by email.
    Used for flows such as email add/remove and password reset.
    """

    __tablename__ = "email_codes"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # User ID
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Purpose of the code, e.g. "email_verification" or "password_reset"
    purpose = Column(String(64), nullable=False)

    # Target email address for which the code was generated
    target_email = Column(String(320), nullable=False)

    # Hashed representation of the plain code
    code_hash = Column(LargeBinary, nullable=False)

    # Creation timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Expiration timestamp after which the code becomes invalid
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Number of verification attempts made for this code
    attempts = Column(Integer, nullable=False, default=0)

    # Moment when the code was successfully used or invalidated
    consumed_at = Column(DateTime(timezone=True), nullable=True)
