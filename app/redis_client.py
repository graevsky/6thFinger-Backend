import os
from functools import lru_cache

from dotenv import load_dotenv
from redis import Redis

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_USERNAME = os.getenv("REDIS_USERNAME") or None
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
REDIS_SSL = os.getenv("REDIS_SSL", "0").strip().lower() in ("1", "true", "yes")


@lru_cache()
def get_redis() -> Redis:
    # Keep a single Redis client per process, same idea as db/minio helpers.
    # decode_responses=True returns plain strings instead of bytes.
    return Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        username=REDIS_USERNAME,
        password=REDIS_PASSWORD,
        ssl=REDIS_SSL,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        health_check_interval=30,
    )
