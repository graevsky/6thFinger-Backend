#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${1:-/opt/finger-backend/6thFinger-Backend}"
COMPOSE_FILE="${APP_DIR}/compose.yml"
ENV_FILE="${APP_DIR}/.env"
NETWORK_NAME="finger_backend_net"

require_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "Missing required file: $file" >&2
    exit 1
  fi
}

wait_for_healthy() {
  local container="$1"
  local attempts="${2:-60}"
  local sleep_seconds="${3:-2}"

  for ((i=1; i<=attempts; i++)); do
    status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    echo "[$i/$attempts] $container -> ${status:-unknown}"

    if [[ "$status" == "healthy" ]]; then
      return 0
    fi

    sleep "$sleep_seconds"
  done

  echo "Container $container did not become healthy in time." >&2
  docker logs "$container" --tail 100 || true
  exit 1
}

require_file "$COMPOSE_FILE"
require_file "$ENV_FILE"

cd "$APP_DIR"

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
  docker network create "$NETWORK_NAME"
fi

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config >/dev/null
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" build backend migrate

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" run --rm migrate

docker rm -f finger_backend_caddy >/dev/null 2>&1 || true

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d backend

wait_for_healthy "finger_backend_api"

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps
echo "Backend deploy finished."