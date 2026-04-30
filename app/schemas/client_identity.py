from pydantic import BaseModel, Field


class ClientChallengeOut(BaseModel):
    """Short-lived challenge used as attestation input on the Android client."""

    challenge: str = Field(..., description="Opaque one-time challenge string.")
    expiresAt: str = Field(..., description="UTC expiration timestamp in ISO-8601.")


class ClientAttestationIn(BaseModel):
    """Android Key Attestation payload sent by the official client."""

    challenge: str = Field(
        ..., description="Challenge previously issued by the server."
    )
    publicKey: str = Field(
        ...,
        description="Attested public key encoded as base64 DER SubjectPublicKeyInfo.",
    )
    attestationCertificateChain: list[str] = Field(
        ...,
        description="Base64 DER X.509 certificate chain returned by Android Keystore.",
        min_length=1,
    )
    appVersion: str = Field(
        ..., description="Application version string reported by the client build."
    )


class ClientAttestationOut(BaseModel):
    """Short-lived client session returned after successful attestation verification."""

    clientKeyId: str = Field(
        ..., description="Stable identifier of the attested client key."
    )
    clientSessionToken: str = Field(
        ..., description="Short-lived token used later in signed request headers."
    )
    expiresAt: str = Field(..., description="UTC expiration timestamp in ISO-8601.")
