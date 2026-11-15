#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
import sys
from typing import Iterable


def overlaps(candidate: str, networks: Iterable[tuple[str, str]], allowed_interface: str) -> list[tuple[str, str]]:
    wanted = ipaddress.ip_network(candidate, strict=True)
    conflicts: list[tuple[str, str]] = []
    for source, value in networks:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if source == allowed_interface and network.version == wanted.version and network.subnet_of(wanted):
            continue
        if network.version == wanted.version and network.overlaps(wanted):
            conflicts.append((source, str(network)))
    return conflicts


def route_networks() -> list[tuple[str, str]]:
    result = subprocess.run(
        ["ip", "-j", "-4", "route", "show", "table", "all"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = json.loads(result.stdout or "[]")
    return [(row.get("dev", "route"), row["dst"]) for row in rows if row.get("dst") not in {None, "default"}]


def wireguard_networks() -> list[tuple[str, str]]:
    result = subprocess.run(["wg", "show", "all", "allowed-ips"], check=True, capture_output=True, text=True)
    found: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        interface = fields[0]
        for value in fields[2].split(","):
            if value and value != "(none)":
                found.append((interface, value))
    return found


def docker_networks() -> list[tuple[str, str]]:
    try:
        ids = subprocess.run(
            ["docker", "network", "ls", "-q"], check=True, capture_output=True, text=True
        ).stdout.split()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    if not ids:
        return []
    rows = json.loads(
        subprocess.run(["docker", "network", "inspect", *ids], check=True, capture_output=True, text=True).stdout
    )
    found: list[tuple[str, str]] = []
    for row in rows:
        for config in row.get("IPAM", {}).get("Config") or []:
            if config.get("Subnet"):
                found.append((f"docker:{row.get('Name', 'unknown')}", config["Subnet"]))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether a proposed WGPanel guest subnet overlaps host state")
    parser.add_argument("--guest-cidr", required=True)
    parser.add_argument("--guest-interface", default="wg1")
    parser.add_argument("--nft-file")
    args = parser.parse_args()

    try:
        networks = route_networks() + wireguard_networks() + docker_networks()
        conflicts = overlaps(args.guest_cidr, networks, args.guest_interface)
    except (ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 2

    if conflicts:
        for source, network in conflicts:
            print(f"collision: {args.guest_cidr} overlaps {network} from {source}", file=sys.stderr)
        return 1
    if args.nft_file:
        checked = subprocess.run(["nft", "-c", "-f", args.nft_file], capture_output=True, text=True)
        if checked.returncode:
            print(checked.stderr.strip() or "nft syntax check failed", file=sys.stderr)
            return 2
    print(f"guest preflight ok: {args.guest_cidr} has no detected route/WireGuard/Docker collision")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
