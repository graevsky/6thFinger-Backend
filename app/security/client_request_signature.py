import base64
import datetime
import hashlib
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.client_identity import ClientInstance, ClientSession
from app.redis_client import get_redis
from app.security.android_attestation import is_client_attestation_enabled
from app.services.common import ServiceError, as_utc, now_utc

CLIENT_CLOCK_SKEW_SECONDS = int(os.getenv("CLIENT_CLOCK_SKEW_SECONDS", "300"))
CLIENT_NONCE_KEY_PREFIX = "client:nonce"


@dataclass(frozen=True)
class AuthenticatedClient:
    """Request-scoped attested client identity accepted by the middleware."""

    instance_id: str
    key_id: str
    public_key_sha256: str


def verify_signed_client_request(
    *,
    db: Session,
    method: str,
    path_with_query: str,
    body: bytes,
    headers,
) -> AuthenticatedClient:
    if not is_client_attestation_enabled():
        raise RuntimeError(
            "verify_signed_client_request must not be called when disabled"
        )

    key_id = (headers.get("X-Client-Key-Id") or "").strip()
    session_token = (headers.get("X-Client-Session") or "").strip()
    timestamp_raw = (headers.get("X-Client-Timestamp") or "").strip()
    nonce = (headers.get("X-Client-Nonce") or "").strip()
    body_sha_header = (headers.get("X-Client-Body-SHA256") or "").strip()
    signature_b64 = (headers.get("X-Client-Signature") or "").strip()

    if not all(
        [key_id, session_token, timestamp_raw, nonce, body_sha_header, signature_b64]
    ):
        _err(401, "MISSING_CLIENT_SIGNATURE", "Missing required X-Client-* headers")

    timestamp = _parse_client_timestamp(timestamp_raw)
    if abs((now_utc() - timestamp).total_seconds()) > CLIENT_CLOCK_SKEW_SECONDS:
        _err(
            401,
            "CLIENT_TIMESTAMP_EXPIRED",
            "Client timestamp is outside the allowed window",
        )

    body_sha_actual = _sha256_base64url(body)
    if body_sha_actual != body_sha_header:
        _err(401, "CLIENT_BODY_HASH_MISMATCH", "Request body hash mismatch")

    session_token_hash = hashlib.sha256(session_token.encode("utf-8")).digest()
    session = (
        db.query(ClientSession)
        .filter_by(session_token_hash=session_token_hash, revoked_at=None)
        .first()
    )
    if not session:
        _err(401, "INVALID_CLIENT_SESSION", "Client session is invalid or revoked")

    if as_utc(session.expires_at) <= now_utc():
        _err(401, "CLIENT_SESSION_EXPIRED", "Client session is expired")

    instance = (
        db.query(ClientInstance)
        .filter_by(id=session.client_instance_id, key_id=key_id, revoked_at=None)
        .first()
    )
    if not instance:
        _err(401, "INVALID_CLIENT_KEY", "Client key is invalid or revoked")

    if not _reserve_nonce(key_id, nonce):
        _err(401, "CLIENT_NONCE_REPLAYED", "Client nonce was already used")

    canonical = "\n".join(
        [
            method.upper(),
            path_with_query,
            body_sha_header,
            timestamp_raw,
            nonce,
            session_token,
        ]
    )
    signature = _b64url_decode(signature_b64, "signature")
    if not _verify_signature_with_openssl(
        public_key_der=instance.public_key_der,
        message=canonical.encode("utf-8"),
        signature=signature,
    ):
        _err(401, "INVALID_CLIENT_SIGNATURE", "Client signature verification failed")

    instance.last_seen_at = now_utc()
    db.commit()

    return AuthenticatedClient(
        instance_id=str(instance.id),
        key_id=instance.key_id,
        public_key_sha256=instance.public_key_sha256,
    )


def _parse_client_timestamp(raw: str) -> datetime.datetime:
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return as_utc(datetime.datetime.fromisoformat(raw))
    except Exception:
        _err(
            401,
            "INVALID_CLIENT_TIMESTAMP",
            "Client timestamp is not a valid ISO-8601 instant",
        )


def _sha256_base64url(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str, label: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        _err(401, "INVALID_CLIENT_SIGNATURE", f"Invalid base64url {label}")


def _reserve_nonce(key_id: str, nonce: str) -> bool:
    nonce_key = f"{CLIENT_NONCE_KEY_PREFIX}:{key_id}:{nonce}"
    return bool(
        get_redis().set(
            nonce_key,
            "1",
            ex=max(CLIENT_CLOCK_SKEW_SECONDS, 1),
            nx=True,
        )
    )


def _verify_signature_with_openssl(
    *,
    public_key_der: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    base_dir = Path(os.getenv("CLIENT_ATTESTATION_TMP_DIR", ".attestation_tmp"))
    base_dir.mkdir(parents=True, exist_ok=True)
    suffix = secrets.token_hex(8)
    key_der_path = base_dir / f"verify_key_{suffix}.der"
    key_pem_path = base_dir / f"verify_key_{suffix}.pem"
    data_path = base_dir / f"verify_data_{suffix}.bin"
    sig_path = base_dir / f"verify_sig_{suffix}.bin"
    try:
        key_der_path.write_bytes(public_key_der)
        data_path.write_bytes(message)
        sig_path.write_bytes(signature)

        convert = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-in",
                str(key_der_path),
                "-out",
                str(key_pem_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if convert.returncode != 0:
            return False

        verify = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(key_pem_path),
                "-signature",
                str(sig_path),
                str(data_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return verify.returncode == 0
    except FileNotFoundError:
        _err(
            503,
            "CLIENT_SIGNATURE_VERIFY_UNAVAILABLE",
            "openssl is not available on the server",
        )
    finally:
        for path in (key_der_path, key_pem_path, data_path, sig_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass


def _err(status: int, code: str, detail: str | None = None) -> None:
    payload = {"error": code}
    if detail:
        payload["detail"] = detail
    raise ServiceError(status_code=status, detail=payload)
