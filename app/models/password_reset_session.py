import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class PasswordResetSession(Base):
    """
    Temporary permission to finish password reset.
    Created after the user successfully verifies email code
    or recovery code. The session is short-lived and single-use.
    """

    __tablename__ = "password_reset_sessions"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # User whose password is being reset
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Verification method used to open the reset session
    method = Column(String(32), nullable=False)

    # Creation timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Moment when verification step succeeded
    verified_at = Column(DateTime(timezone=True), nullable=True)

    # Expiration timestamp of the reset session
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Moment when the session was consumed by password reset finish
    consumed_at = Column(DateTime(timezone=True), nullable=True)
