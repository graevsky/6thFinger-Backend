import os
from functools import lru_cache
from minio import Minio

# Shared bucket name for avatar storage
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "avatarts")


@lru_cache()
def get_minio() -> Minio:
    """
    Create and cache a MinIO client instance.
    The client is initialized once per process.
    Bucket existence is also ensured here so avatar code can rely on it.
    """
    endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    secure = os.getenv("MINIO_SECURE", "0").strip().lower() in ("1", "true", "yes")

    client = Minio(
        endpoint=endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
    )

    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)

    return client
