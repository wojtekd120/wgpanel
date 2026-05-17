from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="WGPANEL_", populate_by_name=True)

    database_path: Path = Field(default=Path("wgpanel.db"))
    interface: str = Field(default="wg0")
    wg_config_path: Path = Field(default=Path("/etc/wireguard/wg0.conf"), validation_alias=AliasChoices("WGPANEL_WG_CONFIG_PATH", "WGPANEL_WG_CONFIG"))
    backup_dir: Path = Field(default=Path("/etc/wireguard/backups"))
    helper_path: Path = Field(default=Path("/usr/local/sbin/wgpanel-helper"))
    run_dir: Path = Field(default=Path("/run/wgpanel"))
    network_cidr: str = Field(default="10.8.0.0/24")
    client_address_pool: str = Field(default="10.8.0.0/24")
    server_address: str = Field(default="10.8.0.1")
    server_endpoint: str = Field(default="vpn.example.com:51820")
    server_public_key: str = Field(default="")
    client_dns: str = Field(default="1.1.1.1")
    allowed_ips: str = Field(default="0.0.0.0/0, ::/0")
    auto_disable_expired: bool = Field(default=False)
    session_cookie_name: str = Field(default="wgpanel_session")
    secure_cookies: bool = Field(default=True)
    admin_password_hash: str = Field(default="")


@lru_cache
def get_settings() -> Settings:
    return Settings()
