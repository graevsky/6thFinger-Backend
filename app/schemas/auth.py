from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field
from uuid import UUID


class RegisterParamsOut(BaseModel):
    N: str
    g: str


class RegisterIn(BaseModel):
    username: str
    salt: str
    verifier: str


class RegisterOut(BaseModel):
    detail: str
    recovery_codes: List[str]


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


class EmailStartAddIn(BaseModel):
    email: EmailStr


class EmailConfirmIn(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=32)


class EmailRemoveConfirmIn(BaseModel):
    code: Optional[str] = Field(None, min_length=4, max_length=32)
    recovery_code: Optional[str] = Field(None, min_length=4, max_length=64)


class PasswordResetStartIn(BaseModel):
    username: str


class PasswordResetStartOut(BaseModel):
    has_email: bool
    email: Optional[str] = None
    has_recovery: bool = True


class PasswordResetEmailSendIn(BaseModel):
    username: str
    email: EmailStr


class PasswordResetEmailVerifyIn(BaseModel):
    username: str
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=32)


class PasswordResetRecoveryVerifyIn(BaseModel):
    username: str
    recovery_code: str = Field(..., min_length=4, max_length=64)


class PasswordResetVerifyOut(BaseModel):
    reset_session_id: UUID


class PasswordResetFinishIn(BaseModel):
    reset_session_id: UUID
    new_salt: str
    new_verifier: str


class GenericOk(BaseModel):
    detail: str
