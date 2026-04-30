from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.deps import get_db
from app.schemas.client_identity import (
    ClientAttestationIn,
    ClientAttestationOut,
    ClientChallengeOut,
)
from app.services.client_identity_service import attest_client, issue_client_challenge
from app.services.common import ServiceError

router = APIRouter(prefix="/client", tags=["client"])


def _raise_service_error(exc: ServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get(
    "/challenge",
    response_model=ClientChallengeOut,
    summary="Issue a short-lived client attestation challenge",
)
def client_challenge():
    try:
        return issue_client_challenge()
    except ServiceError as exc:
        _raise_service_error(exc)


@router.post(
    "/attest",
    response_model=ClientAttestationOut,
    summary="Verify Android Key Attestation and create a short-lived client session",
)
def client_attest(body: ClientAttestationIn, db: Session = Depends(get_db)):
    try:
        return attest_client(db, body)
    except ServiceError as exc:
        _raise_service_error(exc)
