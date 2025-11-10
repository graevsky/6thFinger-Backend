import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.models.app_settings import AppSettings
from app.schemas.app_settings import AppSettingsOut, AppSettingsIn

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/", response_model=AppSettingsOut)
def get_settings(user=Depends(get_current_user), db: Session = Depends(get_db)):
    settings = db.query(AppSettings).filter_by(user_id=user.id).first()
    if not settings:
        default_payload = {"tbd": "tbd"}
        settings = AppSettings(user_id=user.id, payload=default_payload)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.put("/", response_model=AppSettingsOut)
def update_settings(
    data: AppSettingsIn, user=Depends(get_current_user), db: Session = Depends(get_db)
):
    settings = db.query(AppSettings).filter_by(user_id=user.id).first()
    if not settings:
        settings = AppSettings(
            user_id=user.id,
            payload=data.payload,
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(settings)
    else:
        settings.payload = data.payload
        settings.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(settings)
    return settings
