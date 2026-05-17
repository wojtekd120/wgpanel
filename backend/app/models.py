from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class CreatePeerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    expires_at: datetime | None = None
    dry_run: bool = False

    @field_validator("name")
    @classmethod
    def name_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Peer name is required")
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def empty_expiration_is_none(cls, value):
        if value == "":
            return None
        return value


class UpdatePeerRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def optional_name_not_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Peer name is required")
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def empty_expiration_is_none(cls, value):
        if value == "":
            return None
        return value


class Peer(BaseModel):
    id: int
    name: str
    notes: str
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
