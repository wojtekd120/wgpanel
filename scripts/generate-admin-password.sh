#!/bin/sh
set -eu

if command -v docker-compose >/dev/null 2>&1; then
  docker-compose run --rm wgpanel hash-password
elif command -v docker >/dev/null 2>&1; then
  docker compose run --rm wgpanel hash-password
else
  echo "Docker Compose is required." >&2
  exit 1
fi

echo "Put the printed hash in .env as WGPANEL_ADMIN_PASSWORD_HASH if you are using advanced hash-based setup."
