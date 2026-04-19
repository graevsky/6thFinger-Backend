import hashlib
import os

from fastapi import HTTPException, Request
from redis.exceptions import RedisError

from app.redis_client import get_redis

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def _client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _normalize_subject(subject: str | None) -> str:
    if not subject:
        return ""
    return subject.strip().lower()


def _bucket(
    scope: str,
    ip: str | None = None,
    subject: str | None = None,
) -> str:
    parts = [scope]

    if ip is not None:
        parts.append(f"ip:{ip}")

    normalized_subject = _normalize_subject(subject)
    if normalized_subject:
        parts.append(f"subject:{normalized_subject}")

    material = "|".join(parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"ratelimit:{scope}:{digest}"


def _hit_limit(key: str, window_sec: int) -> tuple[int, int]:
    redis = get_redis()

    count = redis.incr(key)
    if count == 1:
        redis.expire(key, window_sec)
        ttl = window_sec
    else:
        ttl = redis.ttl(key)
        if ttl is None or ttl < 0:
            ttl = window_sec

    return int(count), int(ttl)


def enforce_rate_limit(
    request: Request,
    scope: str,
    limit: int,
    window_sec: int,
    subject: str | None = None,
    include_ip: bool = True,
) -> None:
    """Best-effort Redis-backed fixed-window rate limit.

    Fails open if Redis is unavailable.
    """
    if not RATE_LIMIT_ENABLED:
        return

    ip = _client_ip(request) if include_ip else None
    key = _bucket(scope=scope, ip=ip, subject=subject)

    try:
        count, ttl = _hit_limit(key, window_sec)
    except RedisError:
        return

    if count > limit:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "TOO_MANY_REQUESTS",
                "detail": f"Too many requests. Retry in {max(ttl, 1)} seconds.",
            },
        )
