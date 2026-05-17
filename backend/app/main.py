import base64
import io
import sqlite3
from datetime import datetime
from pathlib import Path

import qrcode
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config_apply import apply_config_with_helper
from .db import connect, get_db, init_db
from .models import CreatePeerRequest, CreatePeerResponse, Dashboard, LoginRequest, Peer, UpdatePeerRequest, WgPeerStatus
from .security import new_session_token, session_expiry, token_digest, utcnow, verify_password
from .settings import Settings, get_settings
from .validators import validate_peer_name
from .wireguard import (
    allocate_next_ip,
    append_peer_to_config,
    generate_keypair,
    parse_wg_dump,
    read_config,
    render_client_config,
    render_config_with_active_peers,
    render_server_peer_block,
    run_wg_dump,
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


@app.on_event("startup")
def startup() -> None:
    init_db()


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
        if error_type == "missing":
            return JSONResponse(status_code=422, content={"detail": "Missing required field"})
        return JSONResponse(status_code=422, content={"detail": message.replace("Value error, ", "")})
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def row_to_peer(row: sqlite3.Row) -> Peer:
    return Peer(
        id=row["id"],
        name=row["name"],
        notes=row["notes"] if "notes" in row.keys() else "",
        public_key=row["public_key"],
        assigned_ip=row["assigned_ip"],
        created_at=datetime.fromisoformat(row["created_at"]),
        disabled=bool(row["disabled"]),
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
    )


def require_auth(request: Request, settings: Settings = Depends(get_settings)) -> None:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    digest = token_digest(token)
    with connect() as conn:
        row = conn.execute("SELECT expires_at FROM sessions WHERE token_digest = ?", (digest,)).fetchone()
        if not row or datetime.fromisoformat(row["expires_at"]) <= utcnow():
            raise HTTPException(status_code=401, detail="Not authenticated")


@app.post("/api/login")
def login(payload: LoginRequest, response: Response, settings: Settings = Depends(get_settings)) -> dict[str, bool]:
    if not settings.admin_password_hash:
        raise HTTPException(status_code=503, detail="Admin password hash is not configured")
    if not verify_password(payload.password, settings.admin_password_hash):
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
def dashboard(settings: Settings = Depends(get_settings)) -> Dashboard:
    try:
        peers = parse_wg_dump(run_wg_dump(settings.interface))
        up = True
    except Exception:
        peers = []
        up = False
    return Dashboard(
        interface=settings.interface,
        up=up,
        peers=[
            WgPeerStatus(
                public_key=p.public_key,
                endpoint=p.endpoint,
                allowed_ips=p.allowed_ips,
                latest_handshake=p.latest_handshake,
                transfer_rx=p.transfer_rx,
                transfer_tx=p.transfer_tx,
                persistent_keepalive=p.persistent_keepalive,
            )
            for p in peers
        ],
    )


@app.get("/api/peers", response_model=list[Peer], dependencies=[Depends(require_auth)])
def list_peers(db: sqlite3.Connection = Depends(get_db)) -> list[Peer]:
    rows = db.execute("SELECT * FROM peers ORDER BY created_at DESC").fetchall()
    return [row_to_peer(row) for row in rows]


@app.post("/api/peers", response_model=CreatePeerResponse, dependencies=[Depends(require_auth)])
def create_peer(
    payload: CreatePeerRequest,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> CreatePeerResponse:
    name = validate_peer_name(payload.name)
    if not settings.server_public_key:
        raise HTTPException(status_code=503, detail="Server public key is not configured")

    private_key, public_key = generate_keypair()
    used_ips = {row["assigned_ip"] for row in db.execute("SELECT assigned_ip FROM peers").fetchall()}
    try:
        assigned_ip = allocate_next_ip(settings.network_cidr, used_ips)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    now = utcnow()
    peer_block = render_server_peer_block(name, public_key, assigned_ip)
    server_config_preview = append_peer_to_config(read_current_config(settings), peer_block)
    apply_config_with_helper(settings.helper_path, settings.run_dir, server_config_preview, payload.dry_run)

    if payload.dry_run:
        row = {
            "id": 0,
            "name": name,
            "notes": "",
            "public_key": public_key,
            "assigned_ip": assigned_ip,
            "created_at": now.isoformat(),
            "disabled": 0,
            "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
        }
    else:
        db.execute(
            """
        INSERT INTO peers (name, notes, public_key, assigned_ip, created_at, disabled, expires_at)
        VALUES (?, '', ?, ?, ?, 0, ?)
            """,
            (
                name,
                public_key,
                assigned_ip,
                now.isoformat(),
                payload.expires_at.isoformat() if payload.expires_at else None,
            ),
        )
        db.commit()
        row = db.execute("SELECT * FROM peers WHERE public_key = ?", (public_key,)).fetchone()

    client_config = render_client_config(
        private_key,
        assigned_ip,
        settings.server_public_key,
        settings.server_endpoint,
        settings.client_dns,
        settings.allowed_ips,
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
            created_at=datetime.fromisoformat(row["created_at"]),
            disabled=bool(row["disabled"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
        ),
        client_config=client_config,
        qr_png_data_uri=qr,
        server_config_preview=server_config_preview,
        dry_run=payload.dry_run,
    )


def apply_db_config(settings: Settings, db: sqlite3.Connection, dry_run: bool = False) -> str:
    rows = db.execute("SELECT name, public_key, assigned_ip, disabled FROM peers ORDER BY created_at").fetchall()
    peers = [(row["name"], row["public_key"], row["assigned_ip"], bool(row["disabled"])) for row in rows]
    next_config = render_config_with_active_peers(read_current_config(settings), peers)
    apply_config_with_helper(settings.helper_path, settings.run_dir, next_config, dry_run)
    return next_config


def read_current_config(settings: Settings) -> str:
    return read_config(settings.wg_config_path)


def set_peer_disabled(
    peer_id: int,
    disabled: bool,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    row = db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    db.execute("UPDATE peers SET disabled = ? WHERE id = ?", (1 if disabled else 0, peer_id))
    apply_db_config(settings, db)
    db.commit()
    return row_to_peer(db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone())


@app.post("/api/peers/{peer_id}/disable", response_model=Peer, dependencies=[Depends(require_auth)])
def disable_peer(
    peer_id: int,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    return set_peer_disabled(peer_id, True, settings, db)


@app.post("/api/peers/{peer_id}/enable", response_model=Peer, dependencies=[Depends(require_auth)])
def enable_peer(
    peer_id: int,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    return set_peer_disabled(peer_id, False, settings, db)


@app.post("/api/peers/{peer_id}/toggle", response_model=Peer, dependencies=[Depends(require_auth)])
def toggle_peer(
    peer_id: int,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    row = db.execute("SELECT disabled FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    return set_peer_disabled(peer_id, not bool(row["disabled"]), settings, db)


@app.patch("/api/peers/{peer_id}", response_model=Peer, dependencies=[Depends(require_auth)])
def update_peer(
    peer_id: int,
    payload: UpdatePeerRequest,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> Peer:
    row = db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    name = validate_peer_name(payload.name) if payload.name is not None else row["name"]
    notes = payload.notes if payload.notes is not None else row["notes"]
    expires_at = payload.expires_at.isoformat() if payload.expires_at else None
    if payload.expires_at is None and "expires_at" not in payload.model_fields_set:
        expires_at = row["expires_at"]
    db.execute(
        "UPDATE peers SET name = ?, notes = ?, expires_at = ? WHERE id = ?",
        (name, notes, expires_at, peer_id),
    )
    apply_db_config(settings, db)
    db.commit()
    return row_to_peer(db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone())


@app.delete("/api/peers/{peer_id}", dependencies=[Depends(require_auth)])
def delete_peer(
    peer_id: int,
    settings: Settings = Depends(get_settings),
    db: sqlite3.Connection = Depends(get_db),
) -> dict[str, bool]:
    row = db.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    db.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
    apply_db_config(settings, db)
    db.commit()
    return {"ok": True}


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
