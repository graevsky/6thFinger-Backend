import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.models.app_settings import AppSettings
from app.schemas.app_settings import AppSettingsOut, AppSettingsIn
from app.locale.i18n_email import normalize_lang

router = APIRouter(prefix="/settings", tags=["settings"])

DEFAULT_PAYLOAD = {"language": "en"}


@router.get("/", response_model=AppSettingsOut)
def get_settings(user=Depends(get_current_user), db: Session = Depends(get_db)):
    settings = db.query(AppSettings).filter_by(user_id=user.id).first()
    if not settings:
        settings = AppSettings(user_id=user.id, payload=DEFAULT_PAYLOAD)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    else:
        if isinstance(settings.payload, dict) and "language" not in settings.payload:
            merged = dict(settings.payload)
            merged["language"] = "en"
            settings.payload = merged
            settings.updated_at = datetime.datetime.now(datetime.timezone.utc)
            db.commit()
            db.refresh(settings)

    return settings


@router.put("/", response_model=AppSettingsOut)
def update_settings(
    data: AppSettingsIn, user=Depends(get_current_user), db: Session = Depends(get_db)
):
    settings = db.query(AppSettings).filter_by(user_id=user.id).first()

    incoming = data.payload if isinstance(data.payload, dict) else {}
    if "language" in incoming:
        incoming["language"] = normalize_lang(incoming.get("language"), default="en")

    if not settings:
        payload = dict(DEFAULT_PAYLOAD)
        payload.update(incoming)
        settings = AppSettings(
            user_id=user.id,
            payload=payload,
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(settings)
    else:
        current = settings.payload if isinstance(settings.payload, dict) else {}
        merged = dict(current)
        merged.update(incoming)
        if "language" not in merged:
            merged["language"] = "en"
        settings.payload = merged
        settings.updated_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()
    db.refresh(settings)
    return settings
