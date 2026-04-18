from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.schemas.app_settings import AppSettingsOut, AppSettingsIn
from app.services import app_settings_service

router = APIRouter(prefix="/settings", tags=["settings"])

DEFAULT_PAYLOAD = app_settings_service.DEFAULT_PAYLOAD


@router.get("/", response_model=AppSettingsOut)
def get_settings(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return app_settings_service.get_settings(db, user.id)


@router.put("/", response_model=AppSettingsOut)
def update_settings(
    data: AppSettingsIn, user=Depends(get_current_user), db: Session = Depends(get_db)
):
    return app_settings_service.update_settings(db, user.id, data.payload)
