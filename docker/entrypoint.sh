#!/usr/bin/env sh
set -e

echo "Waiting for Postgres at ${DB_HOST}:${DB_PORT}..."

until nc -z "$DB_HOST" "$DB_PORT"; do
  sleep 1
done

echo "Postgres is running"

echo "Running migrations"
alembic upgrade head

echo "Starting server"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload