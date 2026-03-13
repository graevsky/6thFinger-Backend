import hashlib
import os

from dotenv import load_dotenv

load_dotenv()

_CODES_PEPPER = os.getenv("CODES_PEPPER", "dev-pepper-temp-stub")


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_recovery_code(code_plain: str) -> bytes:
    normalized = code_plain.strip().upper()
    payload = f"recovery: {normalized}".encode("utf-8")
    return sha256_digest(_CODES_PEPPER.encode("utf-8") + payload)


def hash_email_code(purpose: str, code_plain: str, targe_email: str) -> bytes:
    p = purpose.strip().lower()
    c = code_plain.strip()
    e = targe_email.strip().lower()
    payload = f"email:{p}:{e}:{c}".encode("utf-8")
    return sha256_digest(_CODES_PEPPER.encode("utf-8") + payload)
