import uuid

from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class Token(Base):
    """
    Persistent token record for one authenticated session.
    Stores the current access token bytes and the hash of the refresh token.
    This allows the backend to revoke sessions and validate logout properly.
    """

    __tablename__ = "tokens"

    # PK
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    # User that owns this token
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Current active access token stored as raw bytes
    access_jti_hash = Column(LargeBinary, nullable=True, index=True)

    # SHA-256 hash of the refresh token
    token_hash = Column(LargeBinary, nullable=False, index=True)

    # Creation timestamp of the token
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Expiration timestamp of the refresh token
    expires_at = Column(DateTime(timezone=True))

    # When set, the token/session is considered revoked
    revoked_at = Column(DateTime(timezone=True))

    # Last successful usage timestamp
    last_used_at = Column(DateTime(timezone=True))
