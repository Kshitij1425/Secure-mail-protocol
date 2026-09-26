"""
API configuration. Every value can be overridden with a SECUREMAILSCOPE_* env var.
"""
from functools import lru_cache
from typing import List, Set

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """API configuration settings."""

    api_title: str = "SecureMailScope API"
    api_version: str = "0.2.0"

    # Upload limits (captures are untrusted input)
    max_upload_size_mb: int = 100
    allowed_extensions: Set[str] = {".pcap", ".pcapng", ".cap"}

    # Analysis resource limits
    max_packets: int = 5_000_000
    analysis_time_budget_seconds: int = 600
    max_concurrent_analyses: int = 2

    database_url: str = "sqlite:///./securemailscope.db"

    # Explicit origins only; never "*" (the dashboard is the only browser client).
    cors_origins: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Bind to loopback by default; exposing the API requires an explicit choice.
    host: str = "127.0.0.1"
    port: int = 8000

    upload_dir: str = "./uploads"
    reports_dir: str = "./reports"

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    model_config = SettingsConfigDict(env_prefix="SECUREMAILSCOPE_")


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
