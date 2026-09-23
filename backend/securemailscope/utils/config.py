from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List

class Settings(BaseSettings):
    """Core settings for SecureMailScope."""

    # Storage
    database_url: str = Field(default="sqlite:///./securemailscope.db", description="SQLAlchemy database URL")

    # Analysis limits
    max_packets: int = Field(default=0, description="Max packets to process (0 = unlimited)")
    max_memory_mb: int = Field(default=2048, description="Safety limit for memory usage")
    timeout_seconds: int = Field(default=600, description="Analysis timeout per PCAP")

    # Policy controls
    strict_mode: bool = Field(default=True, description="Enforce strict protocol conformance")
    tls_versions_deprecated: List[str] = Field(
        default=["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
        description="TLS versions considered deprecated/insecure"
    )

    # API
    api_host: str = Field(default="127.0.0.1", description="FastAPI host binding")
    api_port: int = Field(default=8000, description="FastAPI port binding")

    class Config:
        env_prefix = "SMS_"
        env_file = ".env"

settings = Settings()
