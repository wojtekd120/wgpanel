#!/bin/sh
set -eu

mkdir -p /var/lib/wgpanel /run/wgpanel
chown wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel
chmod 750 /var/lib/wgpanel /run/wgpanel

mkdir -p /etc/wireguard
chown root:wgpanel /etc/wireguard
chmod 750 /etc/wireguard

if [ -f /etc/wireguard/wg0.conf ]; then
  chown root:wgpanel /etc/wireguard/wg0.conf
  chmod 640 /etc/wireguard/wg0.conf
fi

if [ ! -c /dev/net/tun ]; then
  echo "warning: /dev/net/tun is not available; WireGuard operations may fail" >&2
fi

exec sudo -E -u wgpanel /opt/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${WGPANEL_PORT:-8080}"
