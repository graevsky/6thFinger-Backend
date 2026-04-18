from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.minio_client import get_minio
from app.schemas.avatar import AvatarOut
from app.services import avatar_service
from app.services.common import ServiceError

router = APIRouter(prefix="/avatar", tags=["avatar"])


def _raise_service_error(exc: ServiceError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/", response_model=AvatarOut)
async def upload_avatar(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    data = await file.read()

    try:
        result = avatar_service.upload_avatar(
            db=db,
            user=user,
            get_minio_client=get_minio,
            data=data,
            content_type=file.content_type,
        )
    except ServiceError as exc:
        _raise_service_error(exc)

    return AvatarOut(key=result.key, content_type=result.content_type)


@router.get("/")
def get_avatar(user=Depends(get_current_user)):
    try:
        content_type, response = avatar_service.get_avatar_stream(user, get_minio)
    except ServiceError as exc:
        _raise_service_error(exc)

    def iterator():
        try:
            for chunk in response.stream(32 * 1024):
                yield chunk
        finally:
            response.close()
            response.release_conn()

    return StreamingResponse(
        iterator(),
        media_type=content_type,
        headers={"Cache-Control": "no-store"},
    )


@router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
def delete_avatar(
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    avatar_service.delete_avatar(db, user, get_minio)
    return
