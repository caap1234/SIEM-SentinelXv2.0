# app/core/minio_config.py
"""
Configuración de MinIO (S3) para Almacenamiento de Evidencia Cruda e Inmutable.
"""
from __future__ import annotations

import os

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
if os.path.exists("/.dockerenv") and ("localhost" in MINIO_ENDPOINT or "127.0.0.1" in MINIO_ENDPOINT):
    MINIO_ENDPOINT = MINIO_ENDPOINT.replace("localhost", "minio").replace("127.0.0.1", "minio")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET_NAME = os.getenv("MINIO_BUCKET_NAME", "sentinelx-evidence")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_REGION = os.getenv("MINIO_REGION", "us-east-1")

# Estructura jerárquica de rutas S3 por tenant y fecha
# Ejemplo: tenant-acme/2026/08/09/exim_mainlog/evt-12345.json.gz
EVIDENCE_KEY_FORMAT = "{tenant_id}/{year}/{month}/{day}/{source}/{event_id}.json.gz"
