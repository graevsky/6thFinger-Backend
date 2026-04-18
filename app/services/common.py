import datetime
from typing import Any


class ServiceError(Exception):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(str(detail))


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def as_utc(dt_value: datetime.datetime) -> datetime.datetime:
    if dt_value.tzinfo is None:
        return dt_value.replace(tzinfo=datetime.timezone.utc)
    return dt_value.astimezone(datetime.timezone.utc)
