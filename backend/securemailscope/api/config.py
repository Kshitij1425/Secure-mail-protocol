"""
API Configuration and Settings.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Set, List


class Settings(BaseSettings):
    """API configuration settings."""

    # API Settings
    api_title: str = "SecureMailScope API"
    api_version: str = "1.0.0"
    api_prefix: str = "/api/v1"

    # Upload Settings
    max_upload_size_mb: int = 100
    allowed_extensions: Set[str] = {".pcap", ".pcapng", ".cap"}

    # Database
    database_url: str = "sqlite:///./securemailscope.db"

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Paths
    upload_dir: str = "./uploads"
    reports_dir: str = "./reports"

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    model_config = {
        "env_prefix": "SECUREMAILSCOPE_"
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()