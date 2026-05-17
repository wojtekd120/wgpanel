#!/bin/sh
set -eu

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
elif command -v docker >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  fail "docker compose or docker-compose not found"
fi

test -c /dev/net/tun || fail "/dev/net/tun is missing"
test -f /etc/wireguard/wg0.conf || fail "/etc/wireguard/wg0.conf is missing"
sudo wg show wg0 >/dev/null || fail "sudo wg show wg0 failed"
test -f .env || fail ".env is missing; run cp .env.example .env"

grep -q '^WGPANEL_INTERFACE=' .env || fail "WGPANEL_INTERFACE is missing in .env"
grep -q '^WGPANEL_SERVER_ENDPOINT=' .env || fail "WGPANEL_SERVER_ENDPOINT is missing in .env"
grep -q '^WGPANEL_SERVER_PUBLIC_KEY=' .env || fail "WGPANEL_SERVER_PUBLIC_KEY is missing in .env"

MODE="$(stat -c '%a' /etc/wireguard/wg0.conf)"
case "$MODE" in
  *7|*6|*5|*4) fail "/etc/wireguard/wg0.conf is world-readable; use chmod 640 or stricter" ;;
esac

$COMPOSE config >/dev/null || fail "Docker Compose config is invalid"
echo "Preflight checks passed."
