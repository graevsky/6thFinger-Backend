from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field
from uuid import UUID


class RegisterParamsOut(BaseModel):
    """Public SRP constants required by the client before registration or login"""

    N: str = Field(..., description="SRP large safe prime in hex form.")
    g: str = Field(..., description="SRP generator value in hex form.")


class RegisterIn(BaseModel):
    """Payload used to create a new account with client-generated SRP credentials."""

    username: str = Field(..., description="Unique username. Stored in lowercase.")
    salt: str = Field(
        ..., description="SRP salt generated on the client, encoded as hex."
    )
    verifier: str = Field(
        ..., description="SRP verifier generated on the client, encoded as hex."
    )


class RegisterOut(BaseModel):
    """Registration result returned once account creation is complete."""

    detail: str = Field(..., description="Operation result message.")
    recovery_codes: List[str] = Field(
        ..., description="One-time recovery codes returned only at registration time."
    )


class LoginStartIn(BaseModel):
    """Start of SRP login used for identification of user."""

    username: str = Field(..., description="Username of the account to authenticate.")


class LoginStartOut(BaseModel):
    """Server SRP challenge returned to the client for the next login step."""

    salt: str = Field(..., description="Stored SRP salt for the user.")
    B: str = Field(..., description="Server public SRP value.")
    N: str = Field(..., description="SRP large safe prime in hex form.")
    g: str = Field(..., description="SRP generator value in hex form.")


class LoginFinishIn(BaseModel):
    """Second step of SRP login with client proof and public value."""

    username: str = Field(..., description="Username of the account to authenticate.")
    A: str = Field(..., description="Client public SRP value.")
    M1: str = Field(..., description="Client proof calculated during SRP exchange.")
    salt: str = Field(..., description="Salt used by the client during SRP exchange.")
    device_label: str | None = Field(
        None, description="Not used for now. User device label."
    )


class LoginFinishOut(BaseModel):
    """Successful login response containing session tokens."""

    M2: str = Field(
        ..., description="Server proof returned after successful SRP verification."
    )
    access_token: str = Field(..., description="Short-lived JWT access token.")
    refresh_token: str = Field(..., description="Long-lived JWT refresh token.")


class EmailStartAddIn(BaseModel):
    """Request payload for starting verified email attachment flow."""

    email: EmailStr = Field(
        ..., description="Email address that should be attached to the current account."
    )


class EmailConfirmIn(BaseModel):
    """Confirmation payload for verifying email ownership."""

    email: EmailStr = Field(..., description="Email address being confirmed.")
    code: str = Field(
        ..., min_length=4, max_length=32, description="One-time code received by email."
    )


class EmailRemoveConfirmIn(BaseModel):
    """Confirmation payload for removing verified email from the account."""

    code: Optional[str] = Field(
        None,
        min_length=4,
        max_length=32,
        description="One-time code sent to the verified email.",
    )
    recovery_code: Optional[str] = Field(
        None,
        min_length=4,
        max_length=64,
        description="Backup recovery code used when email n/a.",
    )


class PasswordResetStartIn(BaseModel):
    """Request payload for checking available password reset methods."""

    username: str = Field(
        ..., description="Username of the account that should be recovered."
    )


class PasswordResetStartOut(BaseModel):
    """Information about available password reset methods for the user."""

    has_email: bool = Field(
        ..., description="Whether the user has a verified email configured."
    )
    email: Optional[str] = Field(
        None, description="Masked verified email shown to the client when available."
    )
    has_recovery: bool = Field(
        True,
        description="Whether the user still has at least one unused recovery code.",
    )


class PasswordResetEmailSendIn(BaseModel):
    """Request payload for sending password reset code to verified email."""

    username: str = Field(
        ..., description="Username of the account that should be recovered."
    )
    email: EmailStr = Field(
        ..., description="Verified email address expected for this account."
    )


class PasswordResetEmailVerifyIn(BaseModel):
    """Payload for verifying password reset email code."""

    username: str = Field(
        ..., description="Username of the account that should be recovered."
    )
    email: EmailStr = Field(
        ..., description="Verified email address used for password reset."
    )
    code: str = Field(
        ...,
        min_length=4,
        max_length=32,
        description="One-time password reset code received by email.",
    )


class PasswordResetRecoveryVerifyIn(BaseModel):
    """Payload for verifying password reset through a recovery code."""

    username: str = Field(
        ..., description="Username of the account that should be recovered."
    )
    recovery_code: str = Field(
        ...,
        min_length=4,
        max_length=64,
        description="Unused recovery code stored by the user.",
    )


class PasswordResetVerifyOut(BaseModel):
    """Intermediate result of password reset verification step."""

    reset_session_id: UUID = Field(
        ...,
        description="Short-lived password reset session identifier used by the finish step.",
    )


class PasswordResetFinishIn(BaseModel):
    """Final password reset payload with new SRP credentials."""

    reset_session_id: UUID = Field(
        ...,
        description="Password reset session obtained after successful verification.",
    )
    new_salt: str = Field(..., description="New SRP salt generated on the client.")
    new_verifier: str = Field(
        ..., description="New SRP verifier generated on the client."
    )


class GenericOk(BaseModel):
    """Simple success response used by endpoints that only return operation status."""

    detail: str = Field(..., description="Operation result message.")
