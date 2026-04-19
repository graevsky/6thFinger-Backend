import io
from dataclasses import dataclass
from typing import Callable, Any

from sqlalchemy.orm import Session

from app.minio_client import MINIO_BUCKET
from app.models.user import User
from app.services.common import ServiceError


# Maximum accepted avatar size.
MAX_AVATAR_SIZE = 6 * 1024 * 1024  # 6 MB

# Currently supported image types are png, jpeg and webp
SUPPORTED_CONTENT_TYPES = ("image/png", "image/jpeg", "image/webp")


@dataclass(frozen=True)
class AvatarUploadResult:
    """Result key returned after successful avatar upload."""

    key: str
    content_type: str


def ext_for_content_type(ct: str) -> str:
    """Map MIME type to the object key extension."""
    ct = (ct or "").lower()
    if ct == "image/png":
        return "png"
    if ct == "image/webp":
        return "webp"
    return "jpg"


def upload_avatar(
    db: Session,
    user: User,
    get_minio_client: Callable[[], Any],
    data: bytes,
    content_type: str | None,
) -> AvatarUploadResult:
    """Validate and upload a user avatar to object storage."""
    if not content_type:
        raise ServiceError(status_code=400, detail="Missing file")

    normalized_content_type = content_type.lower().strip()
    if normalized_content_type not in SUPPORTED_CONTENT_TYPES:
        raise ServiceError(status_code=400, detail="Unsupported file type")

    if not data:
        raise ServiceError(status_code=400, detail="Empty file")

    if len(data) > MAX_AVATAR_SIZE:
        raise ServiceError(status_code=400, detail="File too large")

    minio_client = get_minio_client()

    ext = ext_for_content_type(normalized_content_type)
    new_key = f"avatars/{user.id}.{ext}"

    old_key = getattr(user, "avatar_key", None)
    if old_key and old_key != new_key:
        try:
            minio_client.remove_object(MINIO_BUCKET, old_key)
        except Exception:
            pass

    minio_client.put_object(
        MINIO_BUCKET,
        new_key,
        io.BytesIO(data),
        length=len(data),
        content_type=normalized_content_type,
    )

    user.avatar_key = new_key
    db.add(user)
    db.commit()
    db.refresh(user)

    return AvatarUploadResult(
        key=new_key,
        content_type=normalized_content_type,
    )


def get_avatar_stream(user: User, get_minio_client: Callable[[], Any]):
    """Return avatar content type and streaming object from storage."""
    key = getattr(user, "avatar_key", None)
    if not key:
        raise ServiceError(status_code=404, detail="No avatar found")

    minio_client = get_minio_client()

    try:
        # Try to use stored object metadata for the content type
        stat_obj = minio_client.stat_object(MINIO_BUCKET, key)
        content_type = stat_obj.content_type or "image/jpeg"
    except Exception:
        # If lookup failed, image sets as jpeg, maybe it ll help.
        content_type = "image/jpeg"

    try:
        response = minio_client.get_object(MINIO_BUCKET, key)
    except Exception:
        raise ServiceError(status_code=404, detail="Avatar not found")

    return content_type, response


def delete_avatar(
    db: Session,
    user: User,
    get_minio_client: Callable[[], Any],
) -> None:
    """Delete avatar object if present and clear avatar reference id from the user."""
    key = getattr(user, "avatar_key", None)
    if key:
        minio_client = get_minio_client()
        try:
            minio_client.remove_object(MINIO_BUCKET, key)
        except Exception:
            pass

    user.avatar_key = None
    db.add(user)
    db.commit()
