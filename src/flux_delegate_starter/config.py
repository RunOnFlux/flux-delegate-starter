"""Configuration management."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings.

    Can be configured via:
    - Environment variables (FLUX_RPC_HOST, etc.)
    - .env file
    - Direct instantiation
    """

    model_config = SettingsConfigDict(
        env_prefix="FLUX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # RPC Configuration
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 16124
    rpc_username: str | None = None
    rpc_password: str | None = None
    rpc_cookie_path: Path | None = None
    rpc_timeout: int = 30

    # Output Configuration
    output_format: str = "rich"  # rich, json, plain
    verbose: bool = False
    debug: bool = False

    def get_cookie_path(self) -> Path:
        """Get RPC cookie path."""
        if self.rpc_cookie_path:
            return Path(self.rpc_cookie_path)
        return Path.home() / ".flux" / ".cookie"


# Global settings instance
settings = Settings()
