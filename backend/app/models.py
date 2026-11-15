from datetime import datetime

from pydantic import BaseModel, Field, field_validator


VALID_TUNNEL_MODES = {"split", "full", "custom"}
VALID_PEER_TYPES = {"private", "guest"}


class LoginRequest(BaseModel):
    username: str = Field(default="admin", max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CreatePeerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    peer_type: str = "private"
    expires_at: datetime | None = None
    dry_run: bool = False
    tunnel_mode: str = "split"
    custom_allowed_ips: str | None = None
    server_allowed_ips: str | None = Field(default=None, max_length=4000)
    client_dns: str | None = None

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

    @field_validator("tunnel_mode")
    @classmethod
    def tunnel_mode_valid(cls, value: str) -> str:
        if value not in VALID_TUNNEL_MODES:
            raise ValueError("Invalid tunnel mode")
        return value

    @field_validator("peer_type")
    @classmethod
    def peer_type_valid(cls, value: str) -> str:
        if value not in VALID_PEER_TYPES:
            raise ValueError("Invalid peer type")
        return value


class UpdatePeerRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    notes: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None
    server_allowed_ips: str | None = Field(default=None, max_length=4000)
    tunnel_mode: str | None = None
    client_allowed_ips: str | None = Field(default=None, max_length=4000)
    client_dns: str | None = Field(default=None, max_length=512)

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

    @field_validator("tunnel_mode")
    @classmethod
    def optional_tunnel_mode_valid(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_TUNNEL_MODES:
            raise ValueError("Invalid tunnel mode")
        return value


class Peer(BaseModel):
    id: int
    name: str
    notes: str
    public_key: str
    assigned_ip: str
    server_allowed_ips: str = ""
    created_at: datetime
    disabled: bool
    expires_at: datetime | None
    managed: bool = True
    peer_type: str = "private"
    tunnel_mode: str = "split"
    client_allowed_ips: str = ""
    client_dns: str = ""
    status: str = "Active"
    interface_name: str = "wg0"


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
    activity_status: str = "Never connected"


class Dashboard(BaseModel):
    interface: str
    up: bool
    peers: list[WgPeerStatus]
    client_address_pool: str = ""
    server_address: str = ""


class OnboardingCheck(BaseModel):
    key: str
    label: str
    state: str
    detail: str
    fix: str = ""


class ConfigDiffRequest(BaseModel):
    include_disabled: bool = False


class TakeOwnershipRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=2000)
    expires_at: datetime | None = None

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


class InterfaceSelectionRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)


class SetupRequest(BaseModel):
    token: str | None = Field(default=None, min_length=16)
    username: str = Field(default="admin", min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)


class RestoreBackupRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=128)


class DiagnosticsFix(BaseModel):
    label: str
    command: str


class DiagnosticsCheck(BaseModel):
    key: str
    group: str
    label: str
    state: str
    detail: str
    fixes: list[DiagnosticsFix] = []
