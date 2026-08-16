"""Application settings loaded from environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Nigehbaan"
    secret_key: str = "change-me-to-a-long-random-string"
    cors_origins: str = "http://localhost:8000"
    database_url: str = "sqlite:///./nigehbaan.db"
    access_token_expire_minutes: int = 60
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4
    rate_limit_per_minute: int = 30
    is_vercel: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache

def get_settings() -> Settings:
    return Settings()
