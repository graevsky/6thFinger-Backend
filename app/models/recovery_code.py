import uuid

from sqlalchemy import Column, DateTime, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class RecoveryCode(Base):
    """
    Backup recovery code for account recovery flows.
    Recovery codes are generated once, stored only as hashes,
    and can be used a single time.
    """

    __tablename__ = "recovery_codes"

    # PK
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)

    # User that owns this recovery code
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Hashed representation of the recovery code
    code_hash = Column(LargeBinary, nullable=False)

    # Creation timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Moment when the recovery code was used
    used_at = Column(DateTime(timezone=True), nullable=True)