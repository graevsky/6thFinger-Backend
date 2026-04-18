from sqlalchemy.orm import Session

from app.locale.i18n_email import normalize_lang
from app.models.app_settings import AppSettings
from app.services.common import now_utc


DEFAULT_PAYLOAD = {"language": "en"}


def get_settings(db: Session, user_id) -> AppSettings:
    settings = db.query(AppSettings).filter_by(user_id=user_id).first()

    if not settings:
        settings = AppSettings(user_id=user_id, payload=dict(DEFAULT_PAYLOAD))
        db.add(settings)
        db.commit()
        db.refresh(settings)
        return settings

    if isinstance(settings.payload, dict) and "language" not in settings.payload:
        merged = dict(settings.payload)
        merged["language"] = "en"
        settings.payload = merged
        settings.updated_at = now_utc()
        db.commit()
        db.refresh(settings)

    return settings


def update_settings(db: Session, user_id, payload: dict) -> AppSettings:
    settings = db.query(AppSettings).filter_by(user_id=user_id).first()

    incoming = payload if isinstance(payload, dict) else {}
    incoming = dict(incoming)

    if "language" in incoming:
        incoming["language"] = normalize_lang(incoming.get("language"), default="en")

    if not settings:
        merged_payload = dict(DEFAULT_PAYLOAD)
        merged_payload.update(incoming)

        settings = AppSettings(
            user_id=user_id,
            payload=merged_payload,
            updated_at=now_utc(),
        )
        db.add(settings)
    else:
        current = settings.payload if isinstance(settings.payload, dict) else {}
        merged_payload = dict(current)
        merged_payload.update(incoming)

        if "language" not in merged_payload:
            merged_payload["language"] = "en"

        settings.payload = merged_payload
        settings.updated_at = now_utc()

    db.commit()
    db.refresh(settings)
    return settings
