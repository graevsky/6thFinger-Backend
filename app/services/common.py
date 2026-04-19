import datetime
from typing import Any


class ServiceError(Exception):
    """
    Application-level error used inside services.

    Routes convert this exception into HTTPException, which keeps
    service logic independent from FastAPI internals.
    """

    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(str(detail))


def now_utc() -> datetime.datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.datetime.now(datetime.timezone.utc)


def as_utc(dt_value: datetime.datetime) -> datetime.datetime:
    """
    Convert datetime to timezone-aware UTC.
    """
    if dt_value.tzinfo is None:
        return dt_value.replace(tzinfo=datetime.timezone.utc)
    return dt_value.astimezone(datetime.timezone.utc)
