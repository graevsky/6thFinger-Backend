#!/usr/bin/env sh
set -eu

echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
until nc -z "$DB_HOST" "$DB_PORT"; do
  sleep 1
done

echo "Running alembic migrations..."
alembic upgrade head

echo "Migrations completed successfully"