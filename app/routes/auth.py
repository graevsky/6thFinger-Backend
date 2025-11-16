import hashlib
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from srptools import SRPContext, SRPServerSession
from srptools.constants import PRIME_2048, PRIME_2048_GEN

from app.schemas.auth import *
from app.security import srp as srp_utils, tokens
from app.db import SessionLocal
from app.models.user import User
from app.models.token import Token
from app.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

# session storage
active_sessions: dict[str, SRPServerSession] = {}
PRIME = PRIME_2048
GENERATOR = PRIME_2048_GEN


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# remove in future
@router.get("/params", response_model=RegisterParamsOut)
def get_srp_params():
    constants = srp_utils.get_constants()
    return RegisterParamsOut(N=constants["N"], g=constants["g"])


@router.post("/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    username = data.username.lower().strip()
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(
            status_code=409,
            detail={"error": "USERNAME_TAKEN", "detail": "Username already exists"},
        )

    try:
        salt_hex = data.salt.strip().lower()
        verifier_hex = data.verifier.strip().lower()

        if len(salt_hex) % 2 != 0:
            salt_hex = "0" + salt_hex

        if len(verifier_hex) % 2 != 0:
            verifier_hex = "0" + verifier_hex

        salt = bytes.fromhex(salt_hex)
        verifier = bytes.fromhex(verifier_hex)

    except ValueError:
        raise HTTPException(status_code=400, detail="salt/verifier must be hex")

    user = User(username=username, srp_salt=salt, srp_verifier=verifier)
    db.add(user)
    db.commit()
    return {"detail": "registered"}


@router.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn, db: Session = Depends(get_db)):
    username = body.username.lower().strip()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": "USER_NOT_FOUND", "detail": "User not found"},
        )

    verifier_hex = user.srp_verifier.hex()
    ctx = SRPContext(username, "", prime=PRIME, generator=GENERATOR)
    server_session = SRPServerSession(ctx, verifier_hex)
    active_sessions[username] = server_session

    return {
        "salt": user.srp_salt.hex(),
        "B": server_session.public,
        "N": PRIME,
        "g": GENERATOR,
    }


@router.post("/login/finish", response_model=LoginFinishOut)
def login_finish(body: LoginFinishIn, db: Session = Depends(get_db)):
    username = body.username.lower().strip()
    session = active_sessions.get(username)
    if not session:
        raise HTTPException(status_code=400, detail="No active session")

    try:
        session.process(body.A, body.salt)
        client_M1 = body.M1.encode("ascii")
        if not session.verify_proof(client_M1):
            raise ValueError("Proof mismatch")
    except Exception:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "WRONG_PASSWORD",
                "detail": "Invalid username or password",
            },
        )

    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": "USER_NOT_FOUND", "detail": "User not found"},
        )

    access_token = tokens.create_access_token({"sub": str(user.id)})
    refresh_token, refresh_hash, expire = tokens.create_refresh_token(
        {"sub": str(user.id)}
    )

    db.add(
        Token(
            user_id=user.id,
            access_token=access_token.encode(),
            token_hash=refresh_hash,
            expires_at=expire,
        )
    )
    db.commit()
    active_sessions.pop(username, None)

    return {
        "M2": session.key_proof_hash.decode("ascii"),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.post("/refresh")
def refresh_token(old_refresh: dict, db: Session = Depends(get_db)):
    token_str = old_refresh.get("refresh_token")
    if not token_str:
        raise HTTPException(status_code=400, detail="Missing token")

    payload = tokens.verify_token(token_str)
    if not payload or payload.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = hashlib.sha256(token_str.encode()).digest()
    db_token = db.query(Token).filter_by(token_hash=token_hash, revoked_at=None).first()
    if not db_token:
        raise HTTPException(status_code=401, detail="Token revoked or missing")

    new_access = tokens.create_access_token({"sub": payload["sub"]})
    return {"access_token": new_access}


@router.post("/logout")
def logout(user=Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Token).filter_by(user_id=user.id, revoked_at=None).update(
        {"revoked_at": datetime.datetime.now(datetime.timezone.utc)}
    )
    db.commit()
    return {"detail": "logged out"}


@router.get("/me")
def get_me(user=Depends(get_current_user)):
    return {"id": str(user.id), "username": user.username}
