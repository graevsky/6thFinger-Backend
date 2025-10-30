import os
from fastapi import APIRouter, Depends, HTTPException
from app.schemas.auth import *
from app.security import srp as srp_utils
from app.db import SessionLocal
from app.models.user import User
from sqlalchemy.orm import Session
from binascii import hexlify, unhexlify
import srp

router = APIRouter(prefix="/auth", tags=["auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register/start", response_model=RegisterStartOut)
def register_start(data: RegisterStartIn):
    salt = srp_utils.generate_salt()
    return RegisterStartOut(
        salt=hexlify(salt).decode(),
        N=hexlify(srp_utils.N.to_bytes(256, "big")).decode(),
        g=str(srp_utils.g),
    )


@router.post("/register/finish", status_code=201)
def register_finish(data: RegisterFinishIn, db: Session = Depends(get_db)):
    username = data.username.lower().strip()
    existing = db.query(User).filter_by(username=username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")

    salt = srp_utils.generate_salt()
    verifier = unhexlify(data.verifier)
    user = User(username=username, srp_salt=salt, srp_verifier=verifier)

    db.add(user)
    db.commit()
    return {"detail": "registered"}


@router.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=body.username.lower().strip()).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    server = srp.Verifier(
        user.username.encode(),
        user.srp_salt,
        user.srp_verifier,
        bytes(os.urandom(32)),
        srp_utils.N,
        srp_utils.g,
    )
    _, B = server.get_challenge()

    return LoginStartOut(
        salt=hexlify(user.srp_salt).decode(),
        N=hexlify(srp_utils.N.to_bytes(256, "big")).decode(),
        g=str(srp_utils.g),
        B=hexlify(B).decode(),
    )
