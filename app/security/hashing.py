import hashlib
import os

from dotenv import load_dotenv

load_dotenv()

_CODES_PEPPER = os.getenv(
    "CODES_PEPPER", "dev-pepper-temp-stub"
)  # Extra secret for safety


def sha256_digest(data: bytes) -> bytes:
    """Return raw SHA-256 digest for the given byte payload"""
    return hashlib.sha256(data).digest()


def hash_recovery_code(code_plain: str) -> bytes:
    """Hash a recovery code before storing or comparing it.

    Recovery codes are normalized to uppercase so input is case-insensitive.
    A type prefix is included in payload construction to separate hash domains.
    """
    normalized = code_plain.strip().upper()
    payload = f"recovery: {normalized}".encode("utf-8")
    return sha256_digest(_CODES_PEPPER.encode("utf-8") + payload)


def hash_email_code(purpose: str, code_plain: str, targe_email: str) -> bytes:
    """Hash an email verification or reset code.

    The hash includes:
    - purpose: to avoid cross-flow code reuse
    - target email: to bind the code to the specific email
    - plain code itself
    """
    p = purpose.strip().lower()
    c = code_plain.strip()
    e = targe_email.strip().lower()
    payload = f"email:{p}:{e}:{c}".encode("utf-8")
    return sha256_digest(_CODES_PEPPER.encode("utf-8") + payload)


def hash_access_jti(jti: str) -> bytes:
    """Hash JWT access-token JTI before storing it in DB."""
    normalized = jti.strip()
    payload = f"access_jti:{normalized}".encode("utf-8")
    return sha256_digest(_CODES_PEPPER.encode("utf-8") + payload)
