import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class ClientInstance(Base):
    """
    Attested official client installation known to the backend.

    Each row represents one accepted Android Keystore key that passed
    attestation verification against the official package and signing cert.
    """

    __tablename__ = "client_instances"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    # Stable public identifier returned to the app and sent in X-Client-Key-Id.
    key_id = Column(String(64), unique=True, nullable=False, index=True)

    # SubjectPublicKeyInfo DER bytes of the attested signing key.
    public_key_der = Column(LargeBinary, nullable=False)

    # Hex SHA-256 of public_key_der for quick lookup and JWT cnf binding.
    public_key_sha256 = Column(String(64), unique=True, nullable=False, index=True)

    package_name = Column(String(255), nullable=False)
    signing_cert_sha256 = Column(String(95), nullable=False)
    app_version = Column(String(64), nullable=True)

    # Human-readable attestation facts kept for policy decisions and audits.
    attestation_security_level = Column(String(32), nullable=True)
    verified_boot_state = Column(String(32), nullable=True)
    device_locked = Column(Boolean, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class ClientSession(Base):
    """
    Short-lived server session issued after successful client attestation.

    The plain session token is returned once to the app, while only its hash is
    stored in the database.
    """

    __tablename__ = "client_sessions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    client_instance_id = Column(
        UUID(as_uuid=True),
        ForeignKey("client_instances.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    session_token_hash = Column(LargeBinary, unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
