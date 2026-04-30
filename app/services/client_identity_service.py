import datetime
import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.client_identity import ClientInstance, ClientSession
from app.redis_client import get_redis
from app.schemas.client_identity import ClientAttestationIn
from app.security.android_attestation import (
    AttestationVerificationError,
    is_client_attestation_enabled,
    load_android_attestation_policy,
    verify_android_key_attestation,
)
from app.services.common import ServiceError, now_utc

CLIENT_CHALLENGE_TTL_SECONDS = int(os.getenv("CLIENT_CHALLENGE_TTL_SECONDS", "120"))
CLIENT_SESSION_TTL_SECONDS = int(os.getenv("CLIENT_SESSION_TTL_SECONDS", "900"))
CLIENT_CHALLENGE_KEY_PREFIX = "client:challenge"


@dataclass(frozen=True)
class ClientAttestationResult:
    clientKeyId: str
    clientSessionToken: str
    expiresAt: str


def issue_client_challenge() -> dict[str, str]:
    _ensure_attestation_enabled()

    challenge = secrets.token_urlsafe(32)
    challenge_hash = _challenge_hash(challenge)
    get_redis().set(
        f"{CLIENT_CHALLENGE_KEY_PREFIX}:{challenge_hash}",
        "1",
        ex=CLIENT_CHALLENGE_TTL_SECONDS,
    )

    expires_at = now_utc() + datetime.timedelta(seconds=CLIENT_CHALLENGE_TTL_SECONDS)
    return {
        "challenge": challenge,
        "expiresAt": _iso_z(expires_at),
    }


def attest_client(db: Session, body: ClientAttestationIn) -> ClientAttestationResult:
    _ensure_attestation_enabled()
    _consume_challenge_or_401(body.challenge)

    try:
        policy = load_android_attestation_policy()
        verified = verify_android_key_attestation(
            cert_chain_b64=body.attestationCertificateChain,
            expected_challenge=body.challenge,
            provided_public_key_b64=body.publicKey,
            policy=policy,
        )
    except AttestationVerificationError as exc:
        _err(401, "INVALID_CLIENT_ATTESTATION", str(exc))

    instance = (
        db.query(ClientInstance)
        .filter_by(public_key_sha256=verified.public_key_sha256)
        .first()
    )
    if instance and instance.revoked_at is not None:
        _err(401, "CLIENT_KEY_REVOKED", "Attested client key is revoked")

    if not instance:
        instance = ClientInstance(
            key_id=str(uuid.uuid4()),
            public_key_der=verified.public_key_der,
            public_key_sha256=verified.public_key_sha256,
            package_name=verified.package_name,
            signing_cert_sha256=verified.signing_cert_sha256,
            app_version=body.appVersion.strip() or None,
            attestation_security_level=verified.attestation_security_level,
            verified_boot_state=verified.verified_boot_state,
            device_locked=verified.device_locked,
            last_seen_at=now_utc(),
        )
        db.add(instance)
        db.flush()
    else:
        instance.package_name = verified.package_name
        instance.signing_cert_sha256 = verified.signing_cert_sha256
        instance.app_version = body.appVersion.strip() or None
        instance.attestation_security_level = verified.attestation_security_level
        instance.verified_boot_state = verified.verified_boot_state
        instance.device_locked = verified.device_locked
        instance.last_seen_at = now_utc()

    db.query(ClientSession).filter_by(
        client_instance_id=instance.id, revoked_at=None
    ).update({"revoked_at": now_utc()})

    session_token = secrets.token_urlsafe(48)
    expires_at = now_utc() + datetime.timedelta(seconds=CLIENT_SESSION_TTL_SECONDS)
    db.add(
        ClientSession(
            client_instance_id=instance.id,
            session_token_hash=hashlib.sha256(session_token.encode("utf-8")).digest(),
            expires_at=expires_at,
        )
    )
    db.commit()

    return ClientAttestationResult(
        clientKeyId=instance.key_id,
        clientSessionToken=session_token,
        expiresAt=_iso_z(expires_at),
    )


def _ensure_attestation_enabled() -> None:
    if not is_client_attestation_enabled():
        _err(
            503,
            "CLIENT_ATTESTATION_DISABLED",
            "Client attestation is disabled for this backend",
        )


def _consume_challenge_or_401(challenge: str) -> None:
    challenge_hash = _challenge_hash(challenge)
    deleted = get_redis().delete(f"{CLIENT_CHALLENGE_KEY_PREFIX}:{challenge_hash}")
    if not deleted:
        _err(401, "INVALID_OR_EXPIRED_CHALLENGE", "Invalid or expired challenge")


def _challenge_hash(challenge: str) -> str:
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def _iso_z(value: datetime.datetime) -> str:
    return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _err(status: int, code: str, detail: str | None = None) -> None:
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise ServiceError(status_code=status, detail=payload)
