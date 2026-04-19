import os
import jwt
import hashlib
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET")  # JWT secret key from environment
ALGORITHM = "HS256"  # hasing algorithm for JWT
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TTL", 600))  # Access token expiration time
REFRESH_TOKEN_EXPIRE_SECONDS = int(os.getenv("REFRESH_TTL", 2592000))  # Refresh token expiration time


def create_access_token(data: dict) -> str:
    """Generate a signed short-lived access token.

    The token always gets:
    - exp: expiration timestamp
    - typ: explicit token type
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire, "typ": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> tuple[str, bytes, datetime]:
    """Generate a signed refresh token and hash.

    The plain refresh token is returned to the client, while only its SHA-256 hash stored.
    """
    expire = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "typ": "refresh"})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    token_hash = hashlib.sha256(token.encode()).digest()
    return token, token_hash, expire


def verify_token(token: str) -> dict:
    """Decode and validate a JWT.

    Returns decoded payload on success. Otherwise, returns an empty dict.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return {}
