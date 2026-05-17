from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="WGPANEL_")

    database_path: Path = Field(default=Path("wgpanel.db"))
    interface: str = Field(default="wg0")
    wg_config_path: Path = Field(default=Path("/etc/wireguard/wg0.conf"))
    helper_path: Path = Field(default=Path("/usr/local/sbin/wgpanel-helper"))
    run_dir: Path = Field(default=Path("/run/wgpanel"))
    network_cidr: str = Field(default="10.8.0.0/24")
    server_endpoint: str = Field(default="vpn.example.com:51820")
    server_public_key: str = Field(default="")
    client_dns: str = Field(default="1.1.1.1")
    allowed_ips: str = Field(default="0.0.0.0/0, ::/0")
    session_cookie_name: str = Field(default="wgpanel_session")
    secure_cookies: bool = Field(default=True)
    admin_password_hash: str = Field(default="")


@lru_cache
def get_settings() -> Settings:
    return Settings()
