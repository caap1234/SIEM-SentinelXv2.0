# app/services/evidence_service.py
"""
Servicio de Gestión e Integridad Forense de Evidencia Cruda (S3 / MinIO).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

from app.core.minio_config import (
    MINIO_ENDPOINT,
    MINIO_ACCESS_KEY,
    MINIO_SECRET_KEY,
    MINIO_BUCKET_NAME,
    MINIO_SECURE,
    MINIO_REGION,
    EVIDENCE_KEY_FORMAT,
)
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinelx.evidence")

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class EvidenceServiceError(Exception):
    """Excepción base para errores de evidencia S3."""
    pass


class MinioUnavailableError(EvidenceServiceError):
    """Se lanza cuando MinIO / S3 no se encuentra disponible."""
    pass


class EvidenceService:
    _instance: Optional[EvidenceService] = None

    def __init__(self, endpoint: str = MINIO_ENDPOINT) -> None:
        self.endpoint = endpoint
        self.s3_client: Any = None
        self._connected = False

    @classmethod
    def get_instance(cls) -> EvidenceService:
        if cls._instance is None:
            cls._instance = EvidenceService()
        return cls._instance

    def connect(self) -> bool:
        """Inicializa la conexión con el endpoint S3 / MinIO."""
        if not HAS_BOTO3:
            logger.warning("boto3 no instalado; EvidenceService operará en modo offline/mock.")
            return False

        if self._connected and self.s3_client:
            return True

        try:
            cfg = Config(
                signature_version="s3v4",
                connect_timeout=3,
                read_timeout=5,
                retries={"max_attempts": 3},
            )
            self.s3_client = boto3.client(
                "s3",
                endpoint_url=self.endpoint,
                aws_access_key_id=MINIO_ACCESS_KEY,
                aws_secret_access_key=MINIO_SECRET_KEY,
                region_name=MINIO_REGION,
                config=cfg,
                use_ssl=MINIO_SECURE,
            )
            self._connected = True
            self.ensure_bucket_exists()
            return True
        except Exception as e:
            self._connected = False
            logger.warning("No se pudo conectar a MinIO en %s: %s", self.endpoint, e)
            return False

    def ensure_bucket_exists(self, bucket_name: str = MINIO_BUCKET_NAME) -> None:
        """Verifica y crea el bucket de evidencia si no existe."""
        if not self.s3_client:
            return
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError:
            try:
                self.s3_client.create_bucket(Bucket=bucket_name)
                logger.info("Bucket de evidencia S3 creado: %s", bucket_name)
            except Exception as e:
                logger.debug("Bucket %s ya existente o fallo menor: %s", bucket_name, e)

    @staticmethod
    def build_evidence_package(event: NormalizedEvent) -> Tuple[bytes, Dict[str, str]]:
        """
        Empaqueta la evidencia original:
        1. Serializa a JSON.
        2. Calcula Hash SHA-256 de la evidencia cruda.
        3. Comprime el paquete con gzip.
        4. Genera los metadatos de integridad forense.
        """
        doc = event.to_opensearch_doc()
        json_bytes = json.dumps(doc, default=str, indent=2).encode("utf-8")
        uncompressed_size = len(json_bytes)

        # Hash SHA-256 del contenido crudo original
        sha256_hash = hashlib.sha256(json_bytes).hexdigest()

        # Compresión gzip (máximo nivel 9)
        out = BytesIO()
        with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9) as gz:
            gz.write(json_bytes)
        compressed_bytes = out.getvalue()

        ts = event.timestamp_utc
        metadata: Dict[str, str] = {
            "event_id": str(event.event.id),
            "timestamp": ts.isoformat(),
            "source": event.event.dataset or "generic",
            "hostname": event.host.hostname or event.host.name or "unknown",
            "tenant_id": event.tenant.id,
            "sha256": sha256_hash,
            "uncompressed_bytes": str(uncompressed_size),
            "compressed_bytes": str(len(compressed_bytes)),
            "schema_version": event.sentinelx_schema.version,
        }

        return compressed_bytes, metadata

    @staticmethod
    def build_s3_key(event: NormalizedEvent) -> str:
        """Genera la ruta jerárquica S3 por tenant/año/mes/día/fuente/event_id."""
        ts = event.timestamp_utc
        source = (event.event.dataset or "generic").replace(".", "_")
        return EVIDENCE_KEY_FORMAT.format(
            tenant_id=event.tenant.id,
            year=ts.strftime("%Y"),
            month=ts.strftime("%m"),
            day=ts.strftime("%d"),
            source=source,
            event_id=str(event.event.id),
        )

    def upload_evidence(
        self,
        event: NormalizedEvent,
        bucket_name: str = MINIO_BUCKET_NAME,
    ) -> Tuple[str, str, str]:
        """
        Sube la evidencia empaquetada e inmutable a MinIO / S3.
        Retorna (object_key, sha256_hash, bucket_name).
        """
        if not self._connected or not self.s3_client:
            if not self.connect():
                raise MinioUnavailableError("Servicio MinIO S3 no disponible")

        compressed_payload, metadata = self.build_evidence_package(event)
        s3_key = self.build_s3_key(event)

        try:
            self.s3_client.put_object(
                Bucket=bucket_name,
                Key=s3_key,
                Body=compressed_payload,
                ContentType="application/gzip",
                Metadata=metadata,
            )
            logger.info("Evidencia subida a S3: %s (SHA-256: %s)", s3_key, metadata["sha256"])
            return s3_key, metadata["sha256"], bucket_name
        except Exception as e:
            logger.error("Error al subir evidencia a S3 key %s: %s", s3_key, e)
            raise EvidenceServiceError(f"Fallo al subir evidencia a MinIO: {e}") from e

    def retrieve_and_verify_evidence(
        self,
        object_key: str,
        bucket_name: str = MINIO_BUCKET_NAME,
    ) -> Tuple[bytes, Dict[str, str], bool]:
        """
        Descarga la evidencia desde S3, la descomprime y verifica la integridad del Hash SHA-256.
        Retorna (uncompressed_bytes, metadata_dict, is_valid_sha256).
        """
        if not self._connected or not self.s3_client:
            if not self.connect():
                raise MinioUnavailableError("Servicio MinIO S3 no disponible")

        try:
            res = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
            compressed_data = res["Body"].read()
            metadata = res.get("Metadata", {})

            # Descompresión gzip
            with gzip.GzipFile(fileobj=BytesIO(compressed_data), mode="rb") as gz:
                uncompressed_bytes = gz.read()

            # Verificación del Hash SHA-256
            calculated_sha256 = hashlib.sha256(uncompressed_bytes).hexdigest()
            expected_sha256 = metadata.get("sha256", "")
            is_valid = (calculated_sha256.lower() == expected_sha256.lower()) if expected_sha256 else True

            if not is_valid:
                logger.error(
                    "VIOLACIÓN DE INTEGRIDAD FORENSE en %s: calculado=%s vs esperado=%s",
                    object_key,
                    calculated_sha256,
                    expected_sha256,
                )

            return uncompressed_bytes, metadata, is_valid
        except Exception as e:
            logger.error("Fallo al recuperar evidencia S3 %s: %s", object_key, e)
            raise EvidenceServiceError(f"Error al descargar o verificar evidencia: {e}") from e
