#!/usr/bin/env bash
set -euo pipefail

confirm() { read -r -p "$1 [y/N]: " ans; [[ "$ans" == "y" || "$ans" == "Y" ]]; }
need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run with sudo: sudo ./scripts/uninstall-systemd.sh" >&2
    exit 1
  fi
}

need_root

echo "WGPanel native/systemd uninstall"

if confirm "Stop and disable wgpanel service?"; then
  systemctl disable --now wgpanel || true
fi

if confirm "Remove /etc/systemd/system/wgpanel.service?"; then
  rm -f /etc/systemd/system/wgpanel.service
  systemctl daemon-reload
fi

if confirm "Remove /usr/local/sbin/wgpanel-helper?"; then
  rm -f /usr/local/sbin/wgpanel-helper
fi

if confirm "Remove /etc/sudoers.d/wgpanel?"; then
  rm -f /etc/sudoers.d/wgpanel
fi

if confirm "Remove /opt/wgpanel?"; then
  rm -rf /opt/wgpanel
fi

if confirm "Remove /etc/wgpanel?"; then
  rm -rf /etc/wgpanel
fi

if confirm "Remove /var/lib/wgpanel? This deletes the SQLite database."; then
  rm -rf /var/lib/wgpanel
fi

echo "WireGuard configs are left untouched by default."
if confirm "Also remove WireGuard configs under /etc/wireguard? A backup will be created first."; then
  backup="/root/wgpanel-wireguard-backup.$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$backup"
  cp -a /etc/wireguard "$backup/"
  echo "Backup created at $backup"
  rm -rf /etc/wireguard
fi

echo "Uninstall complete."
