# app/workers/opensearch_indexer_worker.py
"""
Worker asíncrono que consume eventos normalizados desde NATS JetStream
e indexa masivamente en OpenSearch Data Streams con manejo de DLQ y reintentos.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.nats_config import (
    STREAM_NORMALIZED,
    SUBJECT_NORMALIZED_HOSTING,
    CONSUMER_INDEXER,
    SUBJECT_DLQ_INDEXING,
)
from app.services.nats_service import NatsService
from app.core.opensearch_client import (
    OpenSearchClient,
    OpenSearchUnavailableError,
    OpenSearchServiceError,
)
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinelx.indexer_worker")


class OpenSearchIndexerWorker:
    def __init__(
        self,
        batch_size: int = 500,
        batch_timeout: float = 1.0,
        stream_name: str = STREAM_NORMALIZED,
        consumer_name: str = CONSUMER_INDEXER,
    ) -> None:
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.stream_name = stream_name
        self.consumer_name = consumer_name
        self.running = False
        self.nats_service = NatsService.get_instance()
        self.opensearch_client = OpenSearchClient.get_instance()

    async def process_batch(self, messages: List[Any]) -> Tuple[int, int, int]:
        """
        Procesa un lote de mensajes de NATS, los indexa en OpenSearch y maneja ACKs/DLQ.
        Retorna (indexados_exito, fallos_dlq, reintentos).
        """
        if not messages:
            return 0, 0, 0

        parsed_events: List[NormalizedEvent] = []
        valid_messages: List[Any] = []
        corrupt_messages: List[Any] = []

        for msg in messages:
            try:
                payload = json.loads(msg.data.decode("utf-8"))
                event = NormalizedEvent.model_validate(payload)
                parsed_events.append(event)
                valid_messages.append(msg)
            except Exception as parse_err:
                logger.error("Mensaje no parseable en worker de indexación: %s", parse_err)
                corrupt_messages.append((msg, str(parse_err)))

        # 1. Tratar mensajes corruptos -> DLQ + ACK
        for msg, reason in corrupt_messages:
            await self.nats_service.publish_dlq(
                payload_dict={"raw_data": msg.data.decode("utf-8", errors="ignore")},
                reason=f"indexer_parse_error: {reason}",
                subject=SUBJECT_DLQ_INDEXING,
            )
            try:
                await msg.ack()
            except Exception:
                pass

        if not parsed_events:
            return 0, len(corrupt_messages), 0

        # 2. Bulk index en OpenSearch
        try:
            success_count, failed_items = self.opensearch_client.bulk_index_events(
                events=parsed_events,
                target_stream="sentinelx-events-hosting-default",
            )
        except OpenSearchUnavailableError as err:
            logger.warning("OpenSearch fuera de línea. Los mensajes NO serán confirmados en NATS: %s", err)
            # NO confirmamos en NATS; JetStream redelivrará
            return 0, 0, len(valid_messages)
        except Exception as e:
            logger.error("Error en indexación masiva: %s", e)
            return 0, 0, len(valid_messages)

        # 3. Confirmar (ACK) mensajes indexados exitosamente
        failed_event_ids = {
            item.get("create", {}).get("_id")
            for item in failed_items
            if isinstance(item, dict)
        }

        indexed_count = 0
        dlq_count = 0

        for msg, event in zip(valid_messages, parsed_events):
            evt_id = str(event.event.id)
            if evt_id in failed_event_ids:
                # Fallo de mapeo específico -> DLQ + ACK
                await self.nats_service.publish_dlq(
                    payload_dict=event.to_opensearch_doc(),
                    reason="opensearch_mapping_rejected",
                    subject=SUBJECT_DLQ_INDEXING,
                )
                try:
                    await msg.ack()
                except Exception:
                    pass
                dlq_count += 1
            else:
                # Éxito -> ACK
                try:
                    await msg.ack()
                    indexed_count += 1
                except Exception as ack_err:
                    logger.debug("Error al enviar ACK a NATS: %s", ack_err)

        return indexed_count, dlq_count + len(corrupt_messages), 0

    async def run_once(self) -> Tuple[int, int, int]:
        """Ejecuta una iteración del ciclo de consumo de NATS JetStream."""
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
            # Timeout normal cuando no hay mensajes nuevos en la cola
            if "timeout" not in str(e).lower():
                logger.debug("Info/Timeout en fetch de NATS: %s", e)
            return 0, 0, 0

    async def start(self) -> None:
        """Inicia el bucle continuo del worker de indexación."""
        self.running = True
        logger.info("Worker de indexación de OpenSearch iniciado.")
        while self.running:
            try:
                indexed, dlq, retries = await self.run_once()
                if indexed > 0:
                    logger.info("Lote procesado por Indexer Worker: %d indexados, %d DLQ", indexed, dlq)
                if retries > 0:
                    await asyncio.sleep(2.0)  # Backoff ante OpenSearch indisponible
                elif indexed == 0:
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Excepción no capturada en Indexer Worker: %s", e)
                await asyncio.sleep(1.0)

    def stop(self) -> None:
        self.running = False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = OpenSearchIndexerWorker()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        worker.stop()

