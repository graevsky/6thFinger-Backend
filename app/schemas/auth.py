from pydantic import BaseModel


class RegisterParamsOut(BaseModel):
    N: str
    g: str


class RegisterIn(BaseModel):
    username: str
    salt: str
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
    salt: str
    device_label: str | None = None


class LoginFinishOut(BaseModel):
    M2: str
    access_token: str
    refresh_token: str
