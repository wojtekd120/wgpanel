# Changelog

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
