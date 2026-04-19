#!/usr/bin/env sh
set -eu

echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
until nc -z "$DB_HOST" "$DB_PORT"; do
  sleep 1
done
echo "PostgreSQL is online"

echo "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."
until nc -z "$REDIS_HOST" "$REDIS_PORT"; do
  sleep 1
done
echo "Redis is online"

MINIO_HOST="${MINIO_ENDPOINT%%:*}"
MINIO_PORT="${MINIO_ENDPOINT##*:}"

echo "Waiting for MinIO at ${MINIO_HOST}:${MINIO_PORT}..."
until nc -z "$MINIO_HOST" "$MINIO_PORT"; do
  sleep 1
done
echo "MinIO is online"

echo "Starting FastAPI app"
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers "${UVICORN_WORKERS:-1}" \
  --proxy-headers \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}" \
  --no-server-header