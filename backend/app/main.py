import base64
import difflib
import io
import os
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

import qrcode
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config_apply import apply_config_with_helper, create_backup_with_helper, read_backup_redacted_with_helper, restore_backup_with_helper
from .db import connect, get_db, init_db
from .guest import InterfaceProfile, interface_profile, profile_for_interface
from .models import ConfigDiffRequest, CreatePeerRequest, CreatePeerResponse, Dashboard, DiagnosticsCheck, InterfaceSelectionRequest, LoginRequest, OnboardingCheck, Peer, RestoreBackupRequest, SetupRequest, TakeOwnershipRequest, UpdatePeerRequest, WgPeerStatus
from .redaction import redact, redact_text
from .security import hash_password, new_session_token, new_setup_token, session_expiry, setup_expiry, token_digest, utcnow, verify_password
from .settings import Settings, get_settings
from .validators import validate_peer_name
from .wireguard import (
    allocate_next_ip,
    allowed_ip_conflicts,
    generate_keypair,
    config_path_for_interface,
    parse_config_peer_blocks,
    parse_wg_dump,
    read_config,
    render_client_config,
    render_config_with_managed_keys,
    run_wg_dump,
    run_wg_interfaces,
    unmanaged_used_ips,
    normalize_server_allowed_ips,
    server_allowed_ips_with_assigned_ip,
    validate_allowed_ips,
    validate_interface_name,
    handshake_activity_status,
)

app = FastAPI(title="WGPanel")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
ATTEMPTS: dict[str, list[datetime]] = {}


@app.on_event("startup")
def startup() -> None:
    init_db()
    with connect() as conn:
        migrate_server_allowed_ips_from_config(conn, get_settings())
        migrate_env_admin(conn, get_settings())
        if not admin_exists(conn) and not get_settings().admin_password_hash:
            if get_settings().host == "0.0.0.0":
                print("First-run setup is active. Complete setup immediately. Do not expose this over the public internet without HTTPS.")
            else:
                print("First-run setup is active. Open WGPanel in a browser to create the admin account.")


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    for error in exc.errors():
        field = error.get("loc", [None])[-1]
        error_type = error.get("type", "")
        message = str(error.get("msg", "Invalid request"))
        if field == "name":
            return JSONResponse(status_code=422, content={"detail": "Peer name is required"})
        if field == "expires_at":
            return JSONResponse(status_code=422, content={"detail": "Invalid expiration date"})
        if field in {"password", "confirm_password"} and "12" in message:
            return JSONResponse(status_code=422, content={"detail": "Password must be at least 12 characters."})
        if field in {"custom_allowed_ips", "server_allowed_ips", "tunnel_mode"}:
            return JSONResponse(status_code=422, content={"detail": "Invalid AllowedIPs"})
        if field == "peer_type":
            return JSONResponse(status_code=422, content={"detail": "Invalid peer type"})
        if error_type == "missing":
            return JSONResponse(status_code=422, content={"detail": "Missing required field"})
        return JSONResponse(status_code=422, content={"detail": redact_text(message.replace("Value error, ", ""))})
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": redact(exc.detail)})


@app.exception_handler(Exception)
def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": redact_text(str(exc) or "Internal server error")})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def get_selected_interface(settings: Settings, db: sqlite3.Connection | None = None) -> str:
    close = False
    if db is None:
        db = connect()
        close = True
    try:
        row = db.execute("SELECT value FROM app_settings WHERE key = 'selected_interface'").fetchone()
        return validate_interface_name(row["value"] if row else settings.interface)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid WireGuard interface name") from exc
    finally:
        if close:
            db.close()


def get_interface_from_request(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> str:
    requested = request.query_params.get("interface")
    try:
        return validate_interface_name(requested) if requested else get_selected_interface(settings, db)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid WireGuard interface name") from exc


def config_path_for_selected_interface(interface: str) -> Path:
    return config_path_for_interface(interface)


def redact_private_keys(config_text: str) -> str:
    return redact_text(config_text)


def backup_path_from_name(settings: Settings, interface: str, name: str) -> Path:
    if Path(name).name != name:
        raise HTTPException(status_code=422, detail="Invalid backup name")
    if not name.startswith(f"{interface}.conf.") or not name.endswith(".bak"):
        raise HTTPException(status_code=422, detail="Backup does not belong to selected interface")
    backup_path = (settings.backup_dir / name).resolve()
    backup_dir = settings.backup_dir.resolve()
    if backup_path.parent != backup_dir:
        raise HTTPException(status_code=422, detail="Invalid backup path")
    if not backup_path.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    return backup_path


def admin_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone() is not None


def migrate_env_admin(conn: sqlite3.Connection, settings: Settings) -> None:
    if admin_exists(conn) or not settings.admin_password_hash:
        return
    conn.execute(
        "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
        ("admin", settings.admin_password_hash, utcnow().isoformat()),
    )
    conn.commit()


def ensure_setup_token(conn: sqlite3.Connection, settings: Settings) -> None:
    if admin_exists(conn) or settings.admin_password_hash:
        return
    token_path = settings.database_path.parent / "setup-token"
    row = conn.execute(
        "SELECT token_digest, expires_at FROM setup_tokens WHERE used = 0 ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if row and datetime.fromisoformat(row["expires_at"]) > utcnow() and token_path.exists():
        return
    token = new_setup_token()
    expires = setup_expiry()
    conn.execute(
        "INSERT INTO setup_tokens (token_digest, created_at, expires_at, used) VALUES (?, ?, ?, 0)",
        (token_digest(token), utcnow().isoformat(), expires.isoformat()),
    )
    conn.commit()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token, encoding="utf-8")
    token_path.chmod(0o600)
    print("First-run setup is active. Complete setup immediately or stop the service.")
    print(redact_text(f"Setup URL: http://127.0.0.1:8080/setup?token={token}"))
    print("Read the one-time setup token from /var/lib/wgpanel/setup-token on the server.")


def setup_required() -> bool:
    with connect() as conn:
        return not admin_exists(conn) and not get_settings().admin_password_hash


def rate_limit(request: Request, bucket: str, limit: int = 10, window_seconds: int = 300) -> None:
    now = utcnow()
    key = f"{bucket}:{request.client.host if request.client else 'unknown'}"
    recent = [
        item
        for item in ATTEMPTS.get(key, [])
        if (now - item).total_seconds() < window_seconds
    ]
    if len(recent) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in a few minutes.")
    recent.append(now)
    ATTEMPTS[key] = recent


def row_to_peer(row: sqlite3.Row) -> Peer:
    expires_at = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
    status = "Disabled" if bool(row["disabled"]) else "Active"
    if expires_at and expires_at <= utcnow():
        status = "Expired"
    return Peer(
        id=row["id"],
        name=row["name"],
        notes=row["notes"] if "notes" in row.keys() else "",
        public_key=row["public_key"],
        assigned_ip=row["assigned_ip"],
        server_allowed_ips=server_allowed_ips_for_row(row),
        created_at=datetime.fromisoformat(row["created_at"]),
        disabled=bool(row["disabled"]),
        expires_at=expires_at,
        managed=bool(row["managed"]) if "managed" in row.keys() else True,
        peer_type=row["peer_type"] if "peer_type" in row.keys() else "private",
        tunnel_mode=row["tunnel_mode"] if "tunnel_mode" in row.keys() else "split",
        client_allowed_ips=row["client_allowed_ips"] if "client_allowed_ips" in row.keys() else "",
        client_dns=row["client_dns"] if "client_dns" in row.keys() else "",
        status=status,
        interface_name=row["interface_name"] if "interface_name" in row.keys() else "wg0",
    )


def unmanaged_peer_from_block(index: int, block, interface: str) -> Peer:
    assigned_ip = ""
    if block.allowed_ips:
        assigned_ip = block.allowed_ips[0].split("/", 1)[0]
    return Peer(
        id=-(index + 1),
        name="Unmanaged peer",
        notes="Existing peer preserved from wg0.conf",
        public_key=block.public_key or "",
        assigned_ip=assigned_ip,
        server_allowed_ips=", ".join(block.allowed_ips),
        created_at=utcnow(),
        disabled=False,
        expires_at=None,
        managed=False,
        peer_type="guest" if interface == get_settings().guest_interface else "private",
        tunnel_mode="unknown",
        client_allowed_ips="",
        client_dns="",
        status="Unmanaged",
        interface_name=interface,
    )


def managed_public_keys_for_interface(db: sqlite3.Connection, interface: str) -> set[str]:
    rows = db.execute("SELECT public_key FROM peers WHERE managed = 1 AND interface_name = ?", (interface,)).fetchall()
    deleted = db.execute("SELECT public_key FROM deleted_peers WHERE interface_name = ?", (interface,)).fetchall()
    return {row["public_key"] for row in rows} | {row["public_key"] for row in deleted}


def server_allowed_ips_for_row(row: sqlite3.Row | dict) -> str:
    keys = row.keys()
    if "server_allowed_ips" in keys and row["server_allowed_ips"]:
        return normalize_server_allowed_ips(row["server_allowed_ips"])
    return server_allowed_ips_with_assigned_ip(row["assigned_ip"])


def migrate_server_allowed_ips_from_config(db: sqlite3.Connection, settings: Settings) -> int:
    """One-way metadata migration; never writes or applies WireGuard config."""
    rows = db.execute(
        "SELECT * FROM peers WHERE managed = 1 AND (server_allowed_ips IS NULL OR server_allowed_ips = '')"
    ).fetchall()
    by_interface: dict[str, dict[str, object]] = {}
    for row in rows:
        interface = row["interface_name"]
        if interface not in by_interface:
            path = settings.wg_config_path if interface == settings.interface else config_path_for_selected_interface(interface)
            blocks = parse_config_peer_blocks(read_config(path)) if path.exists() else []
            by_interface[interface] = {block.public_key: block for block in blocks if block.public_key}
        block = by_interface[interface].get(row["public_key"])
        allowed_ips = block.allowed_ips if block and block.allowed_ips else [server_allowed_ips_with_assigned_ip(row["assigned_ip"])]
        db.execute(
            "UPDATE peers SET server_allowed_ips = ? WHERE id = ?",
            (normalize_server_allowed_ips(allowed_ips), row["id"]),
        )
    if rows:
        db.commit()
    return len(rows)


def ensure_assigned_ip_is_allowed(assigned_ip: str, server_allowed_ips: str) -> None:
    required = server_allowed_ips_with_assigned_ip(assigned_ip)
    normalized = normalize_server_allowed_ips(server_allowed_ips)
    if required not in normalized.split(", "):
        raise HTTPException(
            status_code=422,
            detail=f"Server-side AllowedIPs must include the assigned tunnel address {required}",
        )


def reject_server_allowed_ip_conflicts(
    db: sqlite3.Connection,
    interface: str,
    current_config: str,
    candidate_public_key: str,
    candidate_name: str,
    candidate_allowed_ips: str,
) -> None:
    managed_rows = db.execute(
        "SELECT * FROM peers WHERE managed = 1 AND interface_name = ? AND public_key != ?",
        (interface, candidate_public_key),
    ).fetchall()
    peers = [
        (row["public_key"], row["name"], server_allowed_ips_for_row(row))
        for row in managed_rows
    ]
    known_keys = managed_public_keys_for_interface(db, interface) | {candidate_public_key}
    for index, block in enumerate(parse_config_peer_blocks(current_config)):
        if block.public_key and block.public_key not in known_keys and block.allowed_ips:
            peers.append((block.public_key, f"unmanaged peer #{index + 1}", ", ".join(block.allowed_ips)))
    peers.append((candidate_public_key, candidate_name, candidate_allowed_ips))
    conflicts = allowed_ip_conflicts(peers)
    involving_candidate = [item for item in conflicts if candidate_public_key in (item[0], item[2])]
    if involving_candidate:
        left_key, left_prefix, right_key, right_prefix = involving_candidate[0]
        names = {key: name for key, name, _allowed in peers}
        raise HTTPException(
            status_code=409,
            detail=(
                f"Server-side AllowedIPs conflict: {left_prefix} ({names[left_key]}) overlaps "
                f"{right_prefix} ({names[right_key]}). Each prefix must route to only one peer."
            ),
        )


def running_in_docker() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("WGPANEL_IN_DOCKER") == "true"


def fix_commands(docker_command: str, host_command: str) -> list[dict[str, str]]:
    if running_in_docker():
        return [
            {"label": "Docker Compose V2", "command": f"docker compose exec wgpanel sh -lc '{docker_command}'"},
            {"label": "Docker Compose V1", "command": f"docker-compose exec wgpanel sh -lc '{docker_command}'"},
        ]
    return [{"label": "Systemd host", "command": host_command}]


def require_auth(request: Request, settings: Settings = Depends(get_settings)) -> None:
    if setup_required():
        raise HTTPException(status_code=403, detail="First-run setup is required")
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    digest = token_digest(token)
    with connect() as conn:
        row = conn.execute("SELECT expires_at FROM sessions WHERE token_digest = ?", (digest,)).fetchone()
        if not row or datetime.fromisoformat(row["expires_at"]) <= utcnow():
            raise HTTPException(status_code=401, detail="Not authenticated")


@app.post("/api/login")
def login(payload: LoginRequest, response: Response, request: Request, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    rate_limit(request, "login", limit=12)
    if setup_required():
        raise HTTPException(status_code=403, detail="First-run setup is required")
    with connect() as conn:
        admin = conn.execute("SELECT password_hash FROM admins WHERE username = ?", (payload.username,)).fetchone()
    password_hash = admin["password_hash"] if admin else settings.admin_password_hash
    if not password_hash:
        raise HTTPException(status_code=503, detail="Admin password hash is not configured")
    if not verify_password(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = new_session_token()
    now = utcnow()
    expires = session_expiry()
    with connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token_digest, created_at, expires_at) VALUES (?, ?, ?)",
            (token_digest(token), now.isoformat(), expires.isoformat()),
        )
        conn.commit()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        expires=expires,
    )
    return {"ok": True}


@app.get("/api/setup/status")
def setup_status() -> dict[str, bool]:
    return {"setup_required": setup_required()}


@app.get("/api/interfaces", dependencies=[Depends(require_auth)])
def interfaces() -> dict[str, list[dict[str, object]]]:
    names = set()
    try:
        names.update(run_wg_interfaces())
    except Exception:
        pass
    names.update(path.stem for path in Path("/etc/wireguard").glob("*.conf"))
    settings = get_settings()
    names.add(settings.interface)
    if settings.guest_enabled:
        names.add(settings.guest_interface)
    rows = []
    for name in sorted(names):
        try:
            validate_interface_name(name)
        except ValueError:
            continue
        rows.append({"name": name, "config_exists": config_path_for_selected_interface(name).exists()})
    return {"interfaces": rows}


@app.get("/api/peer-profiles", dependencies=[Depends(require_auth)])
def peer_profiles(settings: Settings = Depends(get_settings)) -> dict[str, object]:
    return {
        "private": {"enabled": True, "interface": settings.interface},
        "guest": {
            "enabled": settings.guest_enabled,
            "interface": settings.guest_interface,
            "pool": settings.guest_client_address_pool,
            "ipv6_enabled": False,
        },
    }


@app.get("/api/settings/interface", dependencies=[Depends(require_auth)])
def current_interface(settings: Settings = Depends(get_settings), db: sqlite3.Connection = Depends(get_db)) -> dict[str, str]:
    return {"interface": get_selected_interface(settings, db)}


@app.post("/api/settings/interface", dependencies=[Depends(require_auth)])
def set_interface(
    payload: InterfaceSelectionRequest,
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, str]:
    try:
        interface = validate_interface_name(payload.interface)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid WireGuard interface name") from exc
    db.execute(
        "INSERT INTO app_settings (key, value) VALUES ('selected_interface', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (interface,),
    )
    db.commit()
    return {"interface": interface}


@app.post("/api/setup")
def complete_setup(payload: SetupRequest, request: Request, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    rate_limit(request, "setup", limit=8)
    if settings.secure_cookies and request.url.scheme != "https":
        raise HTTPException(status_code=400, detail="HTTPS is required when secure cookies are enabled. Set WGPANEL_SECURE_COOKIES=false only for local HTTP testing.")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=422, detail="Passwords do not match")
    with connect() as conn:
        if admin_exists(conn):
            raise HTTPException(status_code=409, detail="Setup is already completed.")
        if settings.admin_password_hash:
            raise HTTPException(status_code=409, detail="Setup is already completed.")
        if payload.token:
            row = conn.execute("SELECT * FROM setup_tokens WHERE token_digest = ? AND used = 0", (token_digest(payload.token),)).fetchone()
            if not row or datetime.fromisoformat(row["expires_at"]) <= utcnow():
                raise HTTPException(status_code=401, detail="Setup token is invalid or expired")
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (payload.username, hash_password(payload.password), utcnow().isoformat()),
        )
        if payload.token:
            conn.execute("UPDATE setup_tokens SET used = 1 WHERE token_digest = ?", (token_digest(payload.token),))
        conn.commit()
    token_path = settings.database_path.parent / "setup-token"
    token_path.unlink(missing_ok=True)
    return {"ok": True}


@app.post("/api/logout", dependencies=[Depends(require_auth)])
def logout(request: Request, response: Response, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        with connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_digest = ?", (token_digest(token),))
            conn.commit()
    response.delete_cookie(settings.session_cookie_name)
    return {"ok": True}


@app.get("/api/dashboard", response_model=Dashboard, dependencies=[Depends(require_auth)])
def dashboard(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> Dashboard:
    if settings.auto_disable_expired:
        with connect() as conn:
            expire_peers(settings, conn)
    try:
        peers = parse_wg_dump(run_wg_dump(interface))
        up = True
    except Exception:
        peers = []
        up = False
    profile = profile_for_interface(settings, interface)
    return Dashboard(
        interface=interface,
        up=up,
        client_address_pool=profile.client_address_pool,
        server_address=profile.server_address,
        peers=[
            WgPeerStatus(
                public_key=p.public_key,
                endpoint=p.endpoint,
                allowed_ips=p.allowed_ips,
                latest_handshake=p.latest_handshake,
                transfer_rx=p.transfer_rx,
                transfer_tx=p.transfer_tx,
                persistent_keepalive=p.persistent_keepalive,
                activity_status=handshake_activity_status(p.latest_handshake),
            )
            for p in peers
        ],
    )


@app.get("/api/diagnostics", response_model=list[DiagnosticsCheck], dependencies=[Depends(require_auth)])
def diagnostics_checks(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> list[DiagnosticsCheck]:
    checks: list[DiagnosticsCheck] = []
    config_path = settings.wg_config_path if interface == settings.interface else config_path_for_selected_interface(interface)

    def add(key: str, group: str, label: str, state: str, detail: str, fixes: list[dict[str, str]] | None = None) -> None:
        checks.append(DiagnosticsCheck(key=key, group=group, label=label, state=state, detail=detail, fixes=fixes or []))

    try:
        active_interfaces = set(run_wg_interfaces())
    except Exception:
        active_interfaces = set()

    if interface in active_interfaces:
        add("interface_exists", "WireGuard", "Selected interface exists", "pass", f"{interface} is active on the host.")
    else:
        add(
            "interface_exists",
            "WireGuard",
            "Selected interface exists",
            "fail",
            f"{interface} is not reported by wg show interfaces.",
            fix_commands(f"wg show interfaces && wg show {interface}", f"sudo systemctl start wg-quick@{interface}"),
        )

    if config_path.exists():
        add("config_exists", "Config files", "WireGuard config exists", "pass", f"{config_path} exists.")
    else:
        add("config_exists", "Config files", "WireGuard config exists", "fail", f"{config_path} is missing.", fix_commands(f"ls -l {config_path}", f"sudo nano {config_path}"))

    try:
        read_config(config_path)
        add("config_readable", "Config files", "Config readable", "pass", "WGPanel can read the WireGuard config.")
    except Exception:
        add(
            "config_readable",
            "Config files",
            "Config readable",
            "fail",
            f"WGPanel cannot read {config_path}.",
            fix_commands(
                f"chown root:wgpanel /etc/wireguard {config_path} && chmod 750 /etc/wireguard && chmod 640 {config_path}",
                f"sudo chown root:wgpanel /etc/wireguard {config_path} && sudo chmod 750 /etc/wireguard && sudo chmod 640 {config_path}",
            ),
        )

    try:
        run_wg_dump(interface)
        add("wg_show", "WireGuard", "wg show works", "pass", f"wg show {interface} dump succeeded.")
    except Exception:
        add("wg_show", "WireGuard", "wg show works", "fail", f"wg show {interface} dump failed.", fix_commands(f"wg show {interface}", f"sudo wg show {interface}"))

    backup_dir = settings.backup_dir
    if backup_dir.exists():
        add("backup_dir", "Backups", "Backup directory exists", "pass", f"{backup_dir} exists. The root-owned helper writes backup files.")
    else:
        add(
            "backup_dir",
            "Backups",
            "Backup directory exists",
            "warn",
            f"{backup_dir} does not exist yet.",
            fix_commands(f"mkdir -p {backup_dir} && chown root:wgpanel {backup_dir} && chmod 750 {backup_dir}", f"sudo mkdir -p {backup_dir} && sudo chown root:wgpanel {backup_dir} && sudo chmod 750 {backup_dir}"),
        )

    helper_fixes = fix_commands(
        "visudo -cf /etc/sudoers.d/wgpanel && sudo -n -l",
        "sudo visudo -cf /etc/sudoers.d/wgpanel && sudo -u wgpanel sudo -n -l",
    ) + fix_commands(
        f"sudo -n {settings.helper_path} self-test",
        f"sudo -u wgpanel sudo -n {settings.helper_path} self-test",
    )
    try:
        result = subprocess.run(
            ["sudo", "-n", str(settings.helper_path), "self-test"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            add("helper_sudo", "Helper/sudo", "Helper sudo permission works", "pass", "Restricted helper self-test succeeded.")
        else:
            add(
                "helper_sudo",
                "Helper/sudo",
                "Helper sudo permission works",
                "warn",
                "Helper permission could not be verified automatically. Peer changes may still work if apply succeeds.",
                helper_fixes,
            )
    except Exception:
        add(
            "helper_sudo",
            "Helper/sudo",
            "Helper sudo permission works",
            "warn",
            "Helper permission could not be verified automatically. Peer changes may still work if apply succeeds.",
            helper_fixes,
        )

    if settings.secure_cookies:
        add("secure_cookies", "HTTPS/security", "Secure cookies enabled", "pass", "Session cookies require HTTPS.")
        add("https_proxy", "HTTPS/security", "HTTPS/reverse proxy", "pass", "Use Caddy, Nginx, or another HTTPS reverse proxy in production.")
    else:
        add("secure_cookies", "HTTPS/security", "Secure cookies enabled", "warn", "Secure cookies are disabled for HTTP testing.", [{"label": "Env", "command": "WGPANEL_SECURE_COOKIES=true"}])
        add("https_proxy", "HTTPS/security", "HTTPS/reverse proxy", "warn", "Do not expose plain HTTP to the internet.", [{"label": "SSH tunnel", "command": "ssh -L 8080:127.0.0.1:8080 user@server"}])

    if running_in_docker():
        add("runtime", "Docker/runtime", "Runtime", "pass", "WGPanel is running in Docker; diagnostics show Docker-aware commands.")
    else:
        add("runtime", "Docker/runtime", "Runtime", "pass", "WGPanel is running as a native/systemd install; diagnostics show host commands.")

    try:
        managed_keys = managed_public_keys_for_interface(db, interface)
        unmanaged_count = sum(
            1
            for block in parse_config_peer_blocks(read_current_config(interface, settings))
            if block.public_key and block.public_key not in managed_keys
        )
        state = "warn" if unmanaged_count else "pass"
        add(
            "unmanaged_peers",
            "WireGuard",
            "Unmanaged peers",
            state,
            f"{unmanaged_count} unmanaged peer{'s' if unmanaged_count != 1 else ''} preserved.",
            [{"label": "Action", "command": "Use Take ownership in the peer list when you want WGPanel to manage an existing peer."}] if unmanaged_count else [],
        )
    except Exception:
        add("unmanaged_peers", "WireGuard", "Unmanaged peers", "warn", "Could not count unmanaged peers until the config is readable.")

    return checks


@app.get("/api/onboarding", response_model=list[DiagnosticsCheck], dependencies=[Depends(require_auth)])
def onboarding_checks(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> list[DiagnosticsCheck]:
    return diagnostics_checks(interface, settings, db)


@app.get("/api/peers", response_model=list[Peer], dependencies=[Depends(require_auth)])
def list_peers(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> list[Peer]:
    rows = db.execute("SELECT * FROM peers WHERE interface_name = ? ORDER BY created_at DESC", (interface,)).fetchall()
    managed = [row_to_peer(row) for row in rows]
    managed_keys = managed_public_keys_for_interface(db, interface)
    unmanaged = [
        unmanaged_peer_from_block(index, block, interface)
        for index, block in enumerate(parse_config_peer_blocks(read_current_config(interface, settings)))
        if block.public_key and block.public_key not in managed_keys
    ]
    return managed + unmanaged


def client_allowed_ips_for_request(payload: CreatePeerRequest, profile: InterfaceProfile) -> str:
    if profile.peer_type == "guest":
        return profile.client_allowed_ips
    if payload.tunnel_mode == "split":
        return profile.client_address_pool
    if payload.tunnel_mode == "full":
        return "0.0.0.0/0, ::/0"
    try:
        return validate_allowed_ips(payload.custom_allowed_ips or "")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/peers", response_model=CreatePeerResponse, dependencies=[Depends(require_auth)])
def create_peer(
    payload: CreatePeerRequest,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> CreatePeerResponse:
    name = validate_peer_name(payload.name)
    try:
        profile = interface_profile(settings, payload.peer_type)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if interface != profile.interface:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{payload.peer_type.title()} peers must be created on {profile.interface}, not {interface}."
            ),
        )
    if not profile.server_public_key:
        raise HTTPException(status_code=503, detail="Server public key is not configured")

    private_key, public_key = generate_keypair()
    current_config = read_current_config(interface, settings)
    managed_keys = managed_public_keys_for_interface(db, interface)
    used_ips = {row["assigned_ip"] for row in db.execute("SELECT assigned_ip FROM peers WHERE interface_name = ?", (interface,)).fetchall()}
    used_ips |= unmanaged_used_ips(current_config, managed_keys)
    try:
        assigned_ip = allocate_next_ip(profile.client_address_pool, used_ips, profile.server_address)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    now = utcnow()
    client_allowed_ips = client_allowed_ips_for_request(payload, profile)
    client_dns = profile.client_dns if profile.peer_type == "guest" else (payload.client_dns or profile.client_dns)
    tunnel_mode = "full" if profile.peer_type == "guest" else payload.tunnel_mode
    try:
        server_allowed_ips = server_allowed_ips_with_assigned_ip(assigned_ip, payload.server_allowed_ips)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if profile.peer_type == "guest" and payload.server_allowed_ips:
        raise HTTPException(status_code=422, detail="Guest peers cannot advertise additional server-side networks")
    reject_server_allowed_ip_conflicts(
        db,
        interface,
        current_config,
        public_key,
        name,
        server_allowed_ips,
    )
    existing_rows = db.execute(
        "SELECT * FROM peers WHERE managed = 1 AND interface_name = ? ORDER BY created_at",
        (interface,),
    ).fetchall()
    preview_peers = [(row["name"], row["public_key"], server_allowed_ips_for_row(row), bool(row["disabled"])) for row in existing_rows]
    preview_peers.append((name, public_key, server_allowed_ips, False))
    server_config_preview = render_config_with_managed_keys(current_config, preview_peers, managed_keys | {public_key})

    if payload.dry_run:
        apply_config_with_helper(settings.helper_path, settings.run_dir, server_config_preview, True, interface)
        row = {
            "id": 0,
            "name": name,
            "notes": "",
            "public_key": public_key,
            "assigned_ip": assigned_ip,
            "server_allowed_ips": server_allowed_ips,
            "created_at": now.isoformat(),
            "disabled": 0,
            "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
            "managed": 1,
            "peer_type": profile.peer_type,
            "tunnel_mode": tunnel_mode,
            "client_allowed_ips": client_allowed_ips,
            "client_dns": client_dns,
            "interface_name": interface,
        }
    else:
        try:
            db.execute("DELETE FROM deleted_peers WHERE interface_name = ? AND public_key = ?", (interface, public_key))
            db.execute(
                """
            INSERT INTO peers (name, notes, public_key, assigned_ip, server_allowed_ips, created_at, disabled, expires_at, managed, peer_type, tunnel_mode, client_allowed_ips, client_dns, interface_name)
            VALUES (?, '', ?, ?, ?, ?, 0, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    public_key,
                    assigned_ip,
                    server_allowed_ips,
                    now.isoformat(),
                    payload.expires_at.isoformat() if payload.expires_at else None,
                    profile.peer_type,
                    tunnel_mode,
                    client_allowed_ips,
                    client_dns,
                    interface,
                ),
            )
            apply_config_with_helper(settings.helper_path, settings.run_dir, server_config_preview, False, interface)
            db.commit()
        except Exception:
            db.rollback()
            raise
        row = db.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,)).fetchone()

    client_config = render_client_config(
        private_key,
        assigned_ip,
        profile.server_public_key,
        profile.server_endpoint,
        client_dns,
        client_allowed_ips,
    )
    image = qrcode.make(client_config)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    qr = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()
    return CreatePeerResponse(
        peer=Peer(
            id=row["id"],
            name=row["name"],
            notes=row["notes"] if "notes" in row.keys() else "",
            public_key=row["public_key"],
            assigned_ip=row["assigned_ip"],
            server_allowed_ips=server_allowed_ips_for_row(row),
            created_at=datetime.fromisoformat(row["created_at"]),
            disabled=bool(row["disabled"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            managed=bool(row["managed"]) if "managed" in row.keys() else True,
            peer_type=row["peer_type"] if "peer_type" in row.keys() else profile.peer_type,
            tunnel_mode=row["tunnel_mode"] if "tunnel_mode" in row.keys() else tunnel_mode,
            client_allowed_ips=row["client_allowed_ips"] if "client_allowed_ips" in row.keys() else client_allowed_ips,
            client_dns=row["client_dns"] if "client_dns" in row.keys() else client_dns,
            status="Active",
            interface_name=interface,
        ),
        client_config=client_config,
        qr_png_data_uri=qr,
        server_config_preview=redact_text(server_config_preview),
        dry_run=payload.dry_run,
    )


def apply_db_config(settings: Settings, db: sqlite3.Connection, dry_run: bool = False, interface: str = "wg0") -> str:
    rows = db.execute(
        "SELECT * FROM peers WHERE managed = 1 AND interface_name = ? ORDER BY created_at",
        (interface,),
    ).fetchall()
    peers = [(row["name"], row["public_key"], server_allowed_ips_for_row(row), bool(row["disabled"])) for row in rows]
    next_config = render_config_with_managed_keys(
        read_current_config(interface, settings),
        peers,
        managed_public_keys_for_interface(db, interface),
    )
    apply_config_with_helper(settings.helper_path, settings.run_dir, next_config, dry_run, interface)
    return next_config


def read_current_config(interface: str, settings: Settings) -> str:
    path = settings.wg_config_path if interface == settings.interface else config_path_for_selected_interface(interface)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"WireGuard config not found for interface {interface}")
    return read_config(path)


def set_peer_disabled(
    peer_id: int,
    disabled: bool,
    interface: str,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, object]:
    row = db.execute("SELECT * FROM peers WHERE id = ? AND managed = 1 AND interface_name = ?", (peer_id, interface)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Managed peer not found")
    if not disabled:
        current_config = read_current_config(interface, settings)
        reject_server_allowed_ip_conflicts(
            db,
            interface,
            current_config,
            row["public_key"],
            row["name"],
            server_allowed_ips_for_row(row),
        )
    db.execute("UPDATE peers SET disabled = ? WHERE id = ?", (1 if disabled else 0, peer_id))
    apply_db_config(settings, db, interface=interface)
    db.commit()
    peer = row_to_peer(db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone())
    return {"detail": "Peer disabled" if disabled else "Peer enabled", "active": not disabled, "peer": peer.model_dump(mode="json")}


@app.post("/api/peers/{peer_id}/disable", dependencies=[Depends(require_auth)])
def disable_peer(
    peer_id: int,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, object]:
    return set_peer_disabled(peer_id, True, interface, settings, db)


@app.post("/api/peers/{peer_id}/enable", dependencies=[Depends(require_auth)])
def enable_peer(
    peer_id: int,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, object]:
    return set_peer_disabled(peer_id, False, interface, settings, db)


@app.post("/api/peers/{peer_id}/toggle", dependencies=[Depends(require_auth)])
def toggle_peer(
    peer_id: int,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, object]:
    row = db.execute("SELECT disabled FROM peers WHERE id = ? AND managed = 1 AND interface_name = ?", (peer_id, interface)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    return set_peer_disabled(peer_id, not bool(row["disabled"]), interface, settings, db)


@app.post("/api/peers/take-ownership", response_model=Peer, dependencies=[Depends(require_auth)])
def take_ownership(
    public_key: str,
    payload: TakeOwnershipRequest,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    blocks = parse_config_peer_blocks(read_current_config(interface, settings))
    block = next((item for item in blocks if item.public_key == public_key), None)
    if not block:
        raise HTTPException(status_code=404, detail="Unmanaged peer not found")
    assigned_ip = block.allowed_ips[0].split("/", 1)[0] if block.allowed_ips else ""
    if not assigned_ip:
        raise HTTPException(status_code=422, detail="Peer has no server-side AllowedIPs to import")
    server_allowed_ips = normalize_server_allowed_ips(block.allowed_ips)
    db.execute(
        """
        INSERT INTO peers (name, notes, public_key, assigned_ip, server_allowed_ips, created_at, disabled, expires_at, managed, peer_type, interface_name)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?, 1, ?, ?)
        """,
        (
            validate_peer_name(payload.name),
            payload.notes,
            public_key,
            assigned_ip,
            server_allowed_ips,
            utcnow().isoformat(),
            payload.expires_at.isoformat() if payload.expires_at else None,
            "guest" if interface == settings.guest_interface else "private",
            interface,
        ),
    )
    db.execute("DELETE FROM deleted_peers WHERE interface_name = ? AND public_key = ?", (interface, public_key))
    db.commit()
    return row_to_peer(db.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,)).fetchone())


@app.patch("/api/peers/{peer_id}", response_model=Peer, dependencies=[Depends(require_auth)])
def update_peer(
    peer_id: int,
    payload: UpdatePeerRequest,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    row = db.execute("SELECT * FROM peers WHERE id = ? AND interface_name = ?", (peer_id, interface)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    name = validate_peer_name(payload.name) if payload.name is not None else row["name"]
    notes = payload.notes if payload.notes is not None else row["notes"]
    expires_at = payload.expires_at.isoformat() if payload.expires_at else None
    if payload.expires_at is None and "expires_at" not in payload.model_fields_set:
        expires_at = row["expires_at"]
    server_allowed_ips = server_allowed_ips_for_row(row)
    if "server_allowed_ips" in payload.model_fields_set:
        try:
            server_allowed_ips = normalize_server_allowed_ips(payload.server_allowed_ips or "")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        ensure_assigned_ip_is_allowed(row["assigned_ip"], server_allowed_ips)
        if row["peer_type"] == "guest" and server_allowed_ips != server_allowed_ips_with_assigned_ip(row["assigned_ip"]):
            raise HTTPException(status_code=422, detail="Guest peers may only use their assigned /32 on the server")
        reject_server_allowed_ip_conflicts(
            db,
            interface,
            read_current_config(interface, settings),
            row["public_key"],
            name,
            server_allowed_ips,
        )
    tunnel_mode = payload.tunnel_mode if payload.tunnel_mode is not None else row["tunnel_mode"]
    client_allowed_ips = row["client_allowed_ips"]
    if "client_allowed_ips" in payload.model_fields_set:
        try:
            client_allowed_ips = validate_allowed_ips(payload.client_allowed_ips or "")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif payload.tunnel_mode is not None:
        if tunnel_mode == "split":
            client_allowed_ips = settings.client_address_pool
        elif tunnel_mode == "full":
            client_allowed_ips = "0.0.0.0/0, ::/0"
    client_dns = payload.client_dns if payload.client_dns is not None else row["client_dns"]
    if row["peer_type"] == "guest":
        guest_profile = interface_profile(settings, "guest")
        tunnel_mode = "full"
        client_allowed_ips = "0.0.0.0/0"
        client_dns = guest_profile.client_dns
    try:
        db.execute(
            """
            UPDATE peers
            SET name = ?, notes = ?, expires_at = ?, server_allowed_ips = ?,
                tunnel_mode = ?, client_allowed_ips = ?, client_dns = ?
            WHERE id = ?
            """,
            (name, notes, expires_at, server_allowed_ips, tunnel_mode, client_allowed_ips, client_dns, peer_id),
        )
        apply_db_config(settings, db, interface=interface)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return row_to_peer(db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone())


@app.delete("/api/peers/{peer_id}", dependencies=[Depends(require_auth)])
def delete_peer(
    peer_id: int,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, bool]:
    row = db.execute("SELECT * FROM peers WHERE id = ? AND managed = 1 AND interface_name = ?", (peer_id, interface)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Managed peer not found")
    try:
        db.execute(
            """
            INSERT INTO deleted_peers (interface_name, public_key, deleted_at)
            VALUES (?, ?, ?)
            ON CONFLICT(interface_name, public_key) DO UPDATE SET deleted_at = excluded.deleted_at
            """,
            (interface, row["public_key"], utcnow().isoformat()),
        )
        db.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
        apply_db_config(settings, db, interface=interface)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"ok": True}


@app.post("/api/config/diff", dependencies=[Depends(require_auth)])
def config_diff(
    payload: ConfigDiffRequest,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, str]:
    current = redact_text(read_current_config(interface, settings))
    candidate = apply_db_config(settings, db, dry_run=True, interface=interface)
    candidate = redact_text(candidate)
    diff = "\n".join(
        difflib.unified_diff(
            current.splitlines(),
            candidate.splitlines(),
            fromfile="current wg0.conf",
            tofile="candidate wg0.conf",
            lineterm="",
        )
    )
    return {"diff": diff}


@app.get("/api/backups", dependencies=[Depends(require_auth)])
def list_backups(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> dict[str, list[dict[str, object]]]:
    backups = []
    if not settings.backup_dir.exists():
        return {"backups": backups}
    for path in sorted(settings.backup_dir.glob(f"{interface}.conf.*.bak"), reverse=True):
        if not path.is_file():
            continue
        stat = path.stat()
        timestamp = path.name.removeprefix(f"{interface}.conf.").removesuffix(".bak")
        backups.append(
            {
                "name": path.name,
                "interface": interface,
                "timestamp": timestamp,
                "size": stat.st_size,
            }
        )
    return {"backups": backups}


@app.get("/api/backups/{backup_name}/diff", dependencies=[Depends(require_auth)])
def backup_diff(
    backup_name: str,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    backup_path = backup_path_from_name(settings, interface, backup_name)
    current = redact_private_keys(read_current_config(interface, settings))
    backup = read_backup_redacted_with_helper(settings.helper_path, interface, backup_path)
    diff = "\n".join(
        difflib.unified_diff(
            current.splitlines(),
            backup.splitlines(),
            fromfile=f"current {interface}.conf",
            tofile=backup_name,
            lineterm="",
        )
    )
    return {"diff": diff}


@app.post("/api/backups", dependencies=[Depends(require_auth)])
def create_backup(
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    create_backup_with_helper(settings.helper_path, interface)
    return {"detail": "Backup created"}


@app.get("/api/backups/{backup_name}/download", dependencies=[Depends(require_auth)])
def download_backup(
    backup_name: str,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> Response:
    backup_path = backup_path_from_name(settings, interface, backup_name)
    redacted = read_backup_redacted_with_helper(settings.helper_path, interface, backup_path)
    return Response(
        content=redacted,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{backup_name}.redacted.txt"'},
    )


@app.post("/api/backups/{backup_name}/restore", dependencies=[Depends(require_auth)])
def restore_backup(
    backup_name: str,
    payload: RestoreBackupRequest,
    interface: str = Depends(get_interface_from_request),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    expected = f"RESTORE {interface}"
    if payload.confirmation != expected:
        raise HTTPException(status_code=422, detail=f'Type "{expected}" to restore this backup')
    backup_path = backup_path_from_name(settings, interface, backup_name)
    restore_backup_with_helper(settings.helper_path, interface, backup_path)
    return {"detail": "Backup restored"}


@app.post("/api/maintenance/expire", dependencies=[Depends(require_auth)])
def expire_peers(settings: Settings = Depends(get_settings), db: sqlite3.Connection = Depends(get_db)) -> dict[str, object]:
    interface = get_selected_interface(settings, db)
    rows = db.execute(
        "SELECT * FROM peers WHERE managed = 1 AND disabled = 0 AND expires_at IS NOT NULL AND expires_at <= ? AND interface_name = ?",
        (utcnow().isoformat(), interface),
    ).fetchall()
    ids = [row["id"] for row in rows]
    if ids:
        db.executemany("UPDATE peers SET disabled = 1 WHERE id = ?", [(peer_id,) for peer_id in ids])
        apply_db_config(settings, db, interface=interface)
        db.commit()
    return {"detail": "Expired peers disabled", "count": len(ids), "peer_ids": ids}


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
