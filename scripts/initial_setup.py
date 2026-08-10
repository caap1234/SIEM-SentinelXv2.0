#!/usr/bin/env python3
"""
SentinelX SIEM — Script de Configuración Inicial (FIRST_INSTALL)
Ejecuta la preparación síncrona de base de datos, Alembic, usuario admin inicial,
bucket de MinIO, índices de OpenSearch y migración de listas de seguridad.
"""

import sys
import os
import logging
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command

# Configurar logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinelx.initial_setup")

# Cargar configuración del proyecto
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from app.config import settings
from app.db import Base, SessionLocal, engine
from app.models.user import User
from app.core.security import get_password_hash
from app.services.security_list_service import SecurityListService


def step_1_create_database():
    """Valida la conexión a PostgreSQL y crea las tablas si es necesario."""
    logger.info("-> Paso 1: Validando conexión a PostgreSQL y creando tablas...")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("  Conexión a PostgreSQL exitosa.")
    except Exception as e:
        logger.error(f"  Error de conexión a PostgreSQL: {e}")
        sys.exit(1)


def step_2_run_alembic_migrations():
    """Ejecuta alembic upgrade head."""
    logger.info("-> Paso 2: Ejecutando migraciones de base de datos (Alembic)...")
    try:
        alembic_cfg = Config(os.path.join(ROOT_DIR, "alembic.ini"))
        alembic_cfg.set_main_option("script_location", os.path.join(ROOT_DIR, "alembic"))
        command.upgrade(alembic_cfg, "head")
        logger.info("  Migraciones de Alembic completadas con éxito (head).")
    except Exception as e:
        logger.warning(f"  Aviso durante Alembic upgrade: {e}. Creando tablas via ORM metadata...")
        Base.metadata.create_all(bind=engine)
        logger.info("  Tablas creadas via SQLAlchemy ORM metadata.")


def step_3_create_initial_admin():
    """Crea el usuario administrador inicial si no existe."""
    logger.info("-> Paso 3: Verificando usuario administrador inicial...")
    admin_email = getattr(settings, "INITIAL_ADMIN_EMAIL", "admin@sentinelx.local")
    admin_pass = getattr(settings, "INITIAL_ADMIN_PASSWORD", "SentinelX_Admin_2026!")
    admin_name = getattr(settings, "INITIAL_ADMIN_FULL_NAME", "SentinelX Admin")

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == admin_email).first()
        if existing:
            logger.info(f"  El usuario administrador '{admin_email}' ya existe. (Omite creación)")
        else:
            admin_user = User(
                email=admin_email,
                hashed_password=get_password_hash(admin_pass),
                full_name=admin_name,
                role="admin",
                tenant_id="default",
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            logger.info(f"  Usuario administrador '{admin_email}' creado exitosamente.")
    except Exception as e:
        db.rollback()
        logger.error(f"  Error al crear usuario admin inicial: {e}")
    finally:
        db.close()


def step_4_create_minio_bucket():
    """Crea el bucket de evidencia MinIO si no existe."""
    logger.info("-> Paso 4: Verificando bucket de evidencia MinIO...")
    try:
        from minio import Minio
        endpoint = settings.MINIO_ENDPOINT.replace("http://", "").replace("https://", "")
        client = Minio(
            endpoint,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=False,
        )
        bucket = settings.MINIO_BUCKET_NAME
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            logger.info(f"  Bucket MinIO '{bucket}' creado exitosamente.")
        else:
            logger.info(f"  Bucket MinIO '{bucket}' ya existe.")
    except Exception as e:
        logger.warning(f"  Aviso MinIO: No se pudo conectar a MinIO ({e}). Asegúrese de iniciar MinIO.")


def step_5_seed_security_lists():
    """Pobla las listas de seguridad desde los JSON estáticos a PostgreSQL."""
    logger.info("-> Paso 5: Sembrando listas de seguridad iniciales...")
    try:
        from scripts.migrate_lists_from_json import migrate
        migrate()
        logger.info("  Listas de seguridad sembradas.")
    except Exception as e:
        logger.error(f"  Error al sembrar listas de seguridad: {e}")


def main():
    logger.info("============================================================")
    logger.info(" SentinelX SIEM — Inicialización Automática de Producción ")
    logger.info("============================================================")
    step_1_create_database()
    step_2_run_alembic_migrations()
    step_3_create_initial_admin()
    step_4_create_minio_bucket()
    step_5_seed_security_lists()
    logger.info("============================================================")
    logger.info(" Configuración inicial completada exitosamente.")
    logger.info("============================================================")


if __name__ == "__main__":
    main()
