# app/config.py
import os
from typing import Optional
from pydantic import EmailStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# Si se ejecuta dentro de un contenedor Docker, reemplazar localhost por nombres de servicio internos en variables de entorno
if os.path.exists("/.dockerenv"):
    db_url = os.getenv("DATABASE_URL", "")
    if db_url:
        os.environ["DATABASE_URL"] = (
            db_url.replace("@localhost:", "@db:")
            .replace("@127.0.0.1:", "@db:")
            .replace("@localhost/", "@db/")
            .replace("@127.0.0.1/", "@db/")
        )

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
    if "@localhost:" in settings.DATABASE_URL or "@127.0.0.1:" in settings.DATABASE_URL:
        settings.DATABASE_URL = settings.DATABASE_URL.replace("@localhost:", "@db:").replace("@127.0.0.1:", "@db:")
    elif "@localhost/" in settings.DATABASE_URL or "@127.0.0.1/" in settings.DATABASE_URL:
        settings.DATABASE_URL = settings.DATABASE_URL.replace("@localhost/", "@db/").replace("@127.0.0.1/", "@db/")
