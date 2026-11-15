# Changelog

## 0.1.9-beta - 2026-11-15

- Added an on-demand two-second traffic snapshot with per-peer and aggregate Mbps rates.
- Measures once after login and only when requested afterward; no background polling or traffic history is stored.
- Supports both the selected private interface and the isolated Guest interface.
- Improved cumulative WireGuard transfer counter formatting.

## 0.1.8-beta - 2026-11-15

- Added an optional, narrowly scoped Guest-to-local-DNS exception for TCP/UDP 53 while keeping every other VPS service blocked.
- Ensured both primary and guest WireGuard configs receive safe container-readable ownership during startup.
- Added a responsive Help tab with safe container, WireGuard, routing, redacted-config, Guest VPN, update, backup, and recovery guidance.
- Added one-click copying of troubleshooting commands customized to the selected interface.

## 0.1.7-beta - 2026-11-15

- Fixed ownership of the persistent SQLite backup directory during container startup.
- Preserved additional prefixes found in active WireGuard runtime during metadata reconciliation.
- Made the Compose healthcheck follow a non-loopback `WGPANEL_HOST` bind address.
- Separated server-side peer AllowedIPs from client-export AllowedIPs in the database, API, renderer, and UI.
- Added migration from existing peer blocks so routed prefixes survive the first post-upgrade apply.
- Preserved unknown directives and comments in managed peer blocks during config round trips.
- Preserved complete managed peer blocks across disable/enable and redacted preshared keys in active and disabled previews.
- Added cross-peer server prefix overlap detection.
- Made helper apply atomic with runtime rollback and root-only config backups.
- Added MkDocs operations, routing, guest-isolation, deployment, and rollback documentation.
- Restricted peer creation to the interface explicitly assigned by its private or guest profile.
- Added an opt-in `wg1` Guest profile with separate endpoint/key/pool, IPv4-only exports, fixed per-peer `/32` routes, and UI client type selection.
- Added a fail-closed nftables guest policy, network-collision preflight, systemd ordering, VPS deployment checklist, isolation tests, and guest rollback.

## 0.1.6-beta

- Marked Docker Compose as the official recommended installation method.
- Marked native/systemd install as experimental and advanced.
- Simplified README Quick Start around Docker Compose.
- Added beta-stable update guidance for Docker-based testers.

## 0.1.5-beta

- Added separate runtime and development backend requirements files.
- Fixed native systemd installer repository copy/preflight flow.
- Improved helper/sudo Diagnostics to use a safe restricted self-test and avoid false hard failures.
- Corrected Docker vs systemd diagnostic commands.
- Refined dark mode to use neutral slate/zinc surfaces instead of green-tinted cards.
- Added CI workflow using the shared dependency files.

## 0.1.4-beta

- Added browser-based first-run admin setup.
- Simplified beginner installation flow.
- Cleaned `.env.example`.
- Moved checklist to Diagnostics.
- Added Docker-aware diagnostic fix commands.
- Added backup management page.
- Fixed deleted managed peers reappearing as unmanaged.
- Improved mobile layout.
- Added MIT license.

## 0.1.3-beta

- Added multi-interface support.
- Added UI interface selector.
- Added secure first-run admin setup.
- Added server-side password reset CLI.
- Improved beginner installation flow.
- Added beginner-friendly README, setup helper, password helper, preflight checks, and clearer Docker troubleshooting.
- Expanded existing WireGuard safety docs.

## 0.1.2-beta

- Added full/split/custom tunnel mode.
- Added custom VPN subnet support.
- Added safer existing WireGuard config handling.
- Added unmanaged/managed peer model.
- Added wg0.conf backups before apply.
- Clarified real enable/disable behavior.
- Clarified expiration behavior.
- Removed bandwidth/data limit UI.
- Added dark mode and mobile UI improvements.
- Improved key management warnings.

## 0.1.1-beta

- Fixed Docker WireGuard config permissions.
- Fixed SQLite threading issue.
- Improved peer create validation errors.
- Improved disable/enable UI state.
- Improved peer details and one-time config UX.
