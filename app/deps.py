from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.token import Token
from app.security import tokens
from app.db import SessionLocal
from app.models.user import User
from app.services.common import now_utc
from app.security.hashing import hash_access_jti

auth_scheme = HTTPBearer()


def get_db():
    """Provide a DB session for a single request and always close it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(auth_scheme), db=Depends(get_db)
):
    """
    Resolve the current user from Authorization token

    Validation is done in several steps:
    - JWT must be decodable and contain user id in "sub"
    - refresh tokens are never accepted as access tokens
    - access token must exist in DB and must not be revoked
    - token owner from DB must match JWT payload
    """
    token = credentials.credentials
    payload = tokens.verify_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )

    token_type = payload.get("typ")

    # Refresh token is explicitly rejected on protected routes
    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    access_jti_hash = hash_access_jti(jti)

    # Access token must be present in storage and still active.
    db_token = (
        db.query(Token)
        .filter_by(access_jti_hash=access_jti_hash, revoked_at=None)
        .first()
    )
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    # Token row must belong to the same user as JWT payload.
    if str(db_token.user_id) != str(payload["sub"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user = db.query(User).filter_by(id=payload["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )

    # Update token usage timestamp so the backend can track recent activity.
    db_token.last_used_at = now_utc()
    db.commit()

    return user
