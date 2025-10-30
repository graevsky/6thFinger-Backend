from pydantic import BaseModel


class RegisterStartIn(BaseModel):
    username: str


class RegisterStartOut(BaseModel):
    salt: str
    N: str
    g: str


class RegisterFinishIn(BaseModel):
    username: str
    verifier: str


class LoginStartIn(BaseModel):
    username: str


class LoginStartOut(BaseModel):
    salt: str
    B: str
    N: str
    g: str


class LoginFinishIn(BaseModel):
    username: str
    A: str
    M1: str
    device_label: str | None = None


class LoginFinishOut(BaseModel):
    M2: str
