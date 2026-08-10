# app/workers/minio_evidence_worker.py
"""
Worker asíncrono que consume eventos de NATS JetStream y almacena la evidencia cruda
en MinIO (S3) con compresión gzip, hash SHA-256 e inmutabilidad forense.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, List, Tuple

from app.core.nats_config import (
    STREAM_NORMALIZED,
    SUBJECT_NORMALIZED_HOSTING,
)
from app.services.nats_service import NatsService
from app.services.evidence_service import (
    EvidenceService,
    MinioUnavailableError,
    EvidenceServiceError,
)
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinelx.evidence_worker")

CONSUMER_EVIDENCE = "raw_evidence_group"
SUBJECT_DLQ_EVIDENCE = "sentinelx.dlq.evidence"


class MinioEvidenceWorker:
    def __init__(
        self,
        batch_size: int = 200,
        batch_timeout: float = 1.0,
        stream_name: str = STREAM_NORMALIZED,
        consumer_name: str = CONSUMER_EVIDENCE,
    ) -> None:
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.stream_name = stream_name
        self.consumer_name = consumer_name
        self.running = False
        self.nats_service = NatsService.get_instance()
        self.evidence_service = EvidenceService.get_instance()

    async def process_batch(self, messages: List[Any]) -> Tuple[int, int, int]:
        """
        Procesa un lote de mensajes NATS enviándolos a MinIO S3 con compresión y SHA-256.
        Retorna (subidos_exito, fallos_dlq, reintentos).
        """
        if not messages:
            return 0, 0, 0

        uploaded_count = 0
        dlq_count = 0
        retry_count = 0

        for msg in messages:
            try:
                payload = json.loads(msg.data.decode("utf-8"))
                event = NormalizedEvent.model_validate(payload)
            except Exception as parse_err:
                logger.error("Error al parsear evento para evidencia S3: %s", parse_err)
                await self.nats_service.publish_dlq(
                    payload_dict={"raw_data": msg.data.decode("utf-8", errors="ignore")},
                    reason=f"evidence_parse_error: {parse_err}",
                    subject=SUBJECT_DLQ_EVIDENCE,
                )
                try:
                    await msg.ack()
                    dlq_count += 1
                except Exception:
                    pass
                continue

            # Subir a MinIO S3
            try:
                key, sha256_hash, bucket = self.evidence_service.upload_evidence(event)
                await msg.ack()
                uploaded_count += 1
            except MinioUnavailableError:
                logger.warning("MinIO fuera de línea. Mensaje NO confirmado en NATS (se reintentará): %s", event.event.id)
                retry_count += 1
            except Exception as e:
                logger.error("Error al subir evidencia de evento %s: %s", event.event.id, e)
                await self.nats_service.publish_dlq(
                    payload_dict=event.to_opensearch_doc(),
                    reason=f"minio_upload_error: {e}",
                    subject=SUBJECT_DLQ_EVIDENCE,
                )
                try:
                    await msg.ack()
                    dlq_count += 1
                except Exception:
                    pass

        return uploaded_count, dlq_count, retry_count

    async def run_once(self) -> Tuple[int, int, int]:
        """Ejecuta una iteración del bucle de consumo de NATS."""
        if not self.nats_service._connected or not self.nats_service.js:
            connected = await self.nats_service.connect()
            if not connected:
                return 0, 0, 0

        try:
            psub = await self.nats_service.js.pull_subscribe(
                subject=SUBJECT_NORMALIZED_HOSTING,
                durable=self.consumer_name,
                stream=self.stream_name,
            )
            messages = await psub.fetch(batch=self.batch_size, timeout=self.batch_timeout)
            return await self.process_batch(messages)
        except Exception as e:
            if "timeout" not in str(e).lower():
                logger.debug("Info/Timeout en fetch de evidencia NATS: %s", e)
            return 0, 0, 0

    async def start(self) -> None:
        """Inicia el bucle continuo del worker de evidencia."""
        self.running = True
        logger.info("MinIO Raw Evidence Worker iniciado.")
        while self.running:
            try:
                uploaded, dlq, retries = await self.run_once()
                if uploaded > 0:
                    logger.info("Lote procesado por Evidence Worker: %d subidos a S3, %d DLQ", uploaded, dlq)
                if retries > 0:
                    await asyncio.sleep(2.0)  # Backoff cuando MinIO está fuera de línea
                elif uploaded == 0:
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Excepción no capturada en Evidence Worker: %s", e)
                await asyncio.sleep(1.0)

    def stop(self) -> None:
        self.running = False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = MinioEvidenceWorker()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        worker.stop()

