from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class CreatePeerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    expires_at: datetime | None = None
    dry_run: bool = False


class Peer(BaseModel):
    id: int
    name: str
    public_key: str
    assigned_ip: str
    created_at: datetime
    disabled: bool
    expires_at: datetime | None


class CreatePeerResponse(BaseModel):
    peer: Peer
    client_config: str
    qr_png_data_uri: str
    server_config_preview: str
    dry_run: bool


class WgPeerStatus(BaseModel):
    public_key: str
    endpoint: str | None
    allowed_ips: list[str]
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: str


class Dashboard(BaseModel):
    interface: str
    up: bool
    peers: list[WgPeerStatus]
