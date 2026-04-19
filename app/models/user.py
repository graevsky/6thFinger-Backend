import uuid

from sqlalchemy import Boolean, Column, DateTime, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class User(Base):
    """
    Application user

    Password itself is never stored. Instead, SRP salt and verifier
    are saved and used during the login handshake.
    """

    __tablename__ = "users"

    # PK
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    # Unique normalized usernam
    username = Column(String(32), unique=True, nullable=False)

    # SRP salt generated on the client during registration/password reset
    srp_salt = Column(LargeBinary, nullable=False)

    # SRP verifier derived from password on the client side
    srp_verifier = Column(LargeBinary, nullable=False)

    # Reserved, not used currently
    is_active = Column(Boolean, default=True, nullable=False)

    # Object storage key of the uploaded avatar image
    avatar_key = Column(String(265), nullable=True)

    # Optional user email
    email = Column(String(320), unique=True, nullable=True)

    # Email ownership verification timestamp
    email_verified_at = Column(DateTime(timezone=True), nullable=True)

    # Creation timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Modification timestamp
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )