import io
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.minio_client import get_minio, MINIO_BUCKET
from app.schemas.avatar import AvatarOut

router = APIRouter(prefix="/avatar", tags=["avatar"])

MAX_AVATAR_SIZE = 6 * 1024 * 1024  # 6 MB


def _ext_for_content_type(ct: str) -> str:
    ct = (ct or "").lower()
    if ct == "image/png":
        return "png"
    if ct == "image/webp":
        return "webp"
    return "jpg"


@router.post("/", response_model=AvatarOut)
async def upload_avatar(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not file or not file.content_type:
        raise HTTPException(status_code=400, detail="Missing file")

    content_type = file.content_type.lower().strip()
    if content_type not in ("image/png", "image/jpeg", "image/webp"):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > MAX_AVATAR_SIZE:
        raise HTTPException(status_code=400, detail="File too large")

    client = get_minio()
    ext = _ext_for_content_type(content_type)
    new_key = f"avatars/{user.id}.{ext}"

    old_key = getattr(user, "avatar_key", None)
    if old_key and old_key != new_key:
        try:
            client.remove_object(MINIO_BUCKET, old_key)
        except Exception:
            pass

    client.put_object(
        MINIO_BUCKET,
        new_key,
        io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    )

    user.avatar_key = new_key
    db.add(user)
    db.commit()
    db.refresh(user)

    return AvatarOut(key=new_key, content_type=content_type)


@router.get("/")
def get_avatar(
    user=Depends(get_current_user),
):
    key = getattr(user, "avatar_key", None)
    if not key:
        raise HTTPException(status_code=404, detail="No avatar found")

    client = get_minio()

    try:
        stat_obj = client.stat_object(MINIO_BUCKET, key)
        content_type = stat_obj.content_type or "image/jpeg"
    except Exception:
        content_type = "image/jpeg"

    try:
        response = client.get_object(MINIO_BUCKET, key)
    except Exception:
        raise HTTPException(status_code=404, detail="Avatar not found")

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
    key = getattr(user, "avatar_key", None)
    if key:
        try:
            get_minio().remove_object(MINIO_BUCKET, key)
        except Exception:
            pass

    user.avatar_key = None
    db.add(user)
    db.commit()
    return
