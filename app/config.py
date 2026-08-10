# app/config.py
import os
from urllib.parse import urlparse, urlunparse
from typing import Optional
from pydantic import EmailStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _fix_docker_hostname(url: str, target_host: str) -> str:
    """Reemplaza localhost/127.0.0.1 por target_host usando urlparse para no dañar contraseñas con caracteres especiales."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
        if parsed.hostname in ("localhost", "127.0.0.1"):
            user_pass = ""
            if parsed.username:
                user_pass += parsed.username
                if parsed.password:
                    user_pass += f":{parsed.password}"
                user_pass += "@"
            port_str = f":{parsed.port}" if parsed.port else ""
            new_netloc = f"{user_pass}{target_host}{port_str}"
            return urlunparse(parsed._replace(netloc=new_netloc))
    except Exception:
        pass
    return url


# Si se ejecuta dentro de un contenedor Docker, corregir localhost por nombres de servicio de Docker
if os.path.exists("/.dockerenv"):
    if "DATABASE_URL" in os.environ:
        os.environ["DATABASE_URL"] = _fix_docker_hostname(os.environ["DATABASE_URL"], "db")
    if "OPENSEARCH_URL" in os.environ:
        os.environ["OPENSEARCH_URL"] = _fix_docker_hostname(os.environ["OPENSEARCH_URL"], "opensearch")
    if "NATS_URL" in os.environ:
        os.environ["NATS_URL"] = _fix_docker_hostname(os.environ["NATS_URL"], "nats")
    if "MINIO_ENDPOINT" in os.environ:
        os.environ["MINIO_ENDPOINT"] = _fix_docker_hostname(os.environ["MINIO_ENDPOINT"], "minio")


class Settings(BaseSettings):
    # --- Backend / JWT / DB ---
    DATABASE_URL: str
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- SMTP / Reset password (opcionales, modo debug si faltan) ---
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None
    from_email: Optional[EmailStr] = None

    # URL base del frontend para armar el link de reset
    frontend_base_url: str = "https://sentinelx.tokyo-03.com/"

    # --- Seed admin (opcional) ---
    INITIAL_ADMIN_EMAIL: Optional[str] = None
    INITIAL_ADMIN_PASSWORD: Optional[str] = None
    INITIAL_ADMIN_FULL_NAME: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

if os.path.exists("/.dockerenv"):
    settings.DATABASE_URL = _fix_docker_hostname(settings.DATABASE_URL, "db")
