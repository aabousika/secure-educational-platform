"""Typed application settings loaded from environment variables and .env."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration; secrets must not be hard-coded in source files."""

    app_name: str = "Secure Educational Platform API"
    environment: str = "development"
    database_url: str
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    fernet_key: str
    certificate_private_key_path: str = "keys/certificate_private_key.pem"
    certificate_public_key_path: str = "keys/certificate_public_key.pem"
    cors_origins: str = "http://127.0.0.1:3000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        """Parse comma-separated CORS origins."""
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return one validated, cached settings object."""
    return Settings()
