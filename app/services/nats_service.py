# app/services/nats_service.py
"""
Servicio asíncrono de publicación e interacción con NATS JetStream.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple
from datetime import datetime

from app.core.nats_config import (
    NATS_URL,
    STREAM_RAW,
    STREAM_NORMALIZED,
    STREAM_DLQ,
    SUBJECT_RAW_HOSTING,
    SUBJECT_NORMALIZED_HOSTING,
    SUBJECT_DLQ_PARSING,
    SUBJECT_LISTS_INVALIDATED,
    SUBJECT_RULES_INVALIDATED,
    JETSTREAM_STREAMS,
)
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinelx.nats")

try:
    import nats
    from nats.js.api import StreamConfig
    HAS_NATS = True
except ImportError:
    HAS_NATS = False


class NatsServiceError(Exception):
    """Excepción base para errores de NATS Service."""
    pass


class NatsUnavailableError(NatsServiceError):
    """Se lanza cuando NATS JetStream no se encuentra disponible (HTTP 503)."""
    pass


class NatsService:
    _instance: Optional[NatsService] = None

    def __init__(self, url: str = NATS_URL) -> None:
        self.url = url
        self.nc: Any = None
        self.js: Any = None
        self._connected = False

    @classmethod
    def get_instance(cls) -> NatsService:
        if cls._instance is None:
            cls._instance = NatsService()
        return cls._instance

    async def connect(self) -> bool:
        """Establece la conexión con el clúster o nodo NATS JetStream."""
        if not HAS_NATS:
            logger.warning("Librería nats-py no instalada; NatsService operará en modo offline/mock.")
            return False

        if self._connected and self.nc and self.nc.is_connected:
            return True

        try:
            self.nc = await nats.connect(
                self.url,
                connect_timeout=3,
                max_reconnect_attempts=5,
                reconnect_time_wait=1,
            )
            self.js = self.nc.jetstream()
            self._connected = True
            logger.info("Conexión exitosa a NATS JetStream en %s", self.url)
            await self.ensure_streams()
            return True
        except Exception as e:
            self._connected = False
            logger.warning("No se pudo conectar a NATS JetStream en %s: %s", self.url, e)
            return False

    async def ensure_streams(self) -> None:
        """Inicializa los streams requeridos si no existen."""
        if not self.js:
            return

        for cfg in JETSTREAM_STREAMS:
            try:
                await self.js.add_stream(
                    name=cfg["name"],
                    subjects=cfg["subjects"],
                    max_age=cfg.get("max_age"),
                    storage=cfg.get("storage", "file"),
                    duplicate_window=cfg.get("duplicate_window"),
                )
                logger.info("Stream NATS verificado: %s", cfg["name"])
            except Exception as e:
                logger.debug("Stream %s ya existe o error menor: %s", cfg["name"], e)

    async def get_kv_store(self, bucket_name: str = "sentinelx_correlation_kv"):
        """Retorna o crea una tienda Key-Value distribuida en NATS JetStream para correlación."""
        if not self._connected or not self.js:
            await self.connect()
        if not self.js:
            return None
        try:
            return await self.js.key_value(bucket=bucket_name)
        except Exception:
            try:
                return await self.js.create_key_value(bucket=bucket_name, ttl=3600)
            except Exception as e:
                logger.debug("Error creando KV bucket %s: %s", bucket_name, e)
                return None

    async def publish_normalized_event(
        self,
        event: NormalizedEvent,
        subject: str = SUBJECT_NORMALIZED_HOSTING,
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Publica un evento canónico normalizado en NATS JetStream.
        Utiliza el campo event.id como cabecera 'Nats-Msg-Id' para deduplicación nativa en JetStream.
        """
        event_dict = event.to_opensearch_doc()
        payload = json.dumps(event_dict, default=str).encode("utf-8")
        headers = {"Nats-Msg-Id": str(event.event.id)}

        if not self._connected or not self.js:
            connected = await self.connect()
            if not connected:
                # Retorna indicando que NATS no está conectado
                raise NatsUnavailableError("Servicio NATS JetStream fuera de línea")

        try:
            ack = await self.js.publish(
                subject=subject,
                payload=payload,
                headers=headers,
                timeout=5,
            )
            seq = getattr(ack, "seq", getattr(ack, "sequence", 0))
            return True, ack.stream, seq
        except Exception as e:
            logger.error("Fallo al publicar evento %s en NATS JetStream: %s", event.event.id, e)
            raise NatsServiceError(f"Fallo al publicar evento en NATS: {e}") from e

    async def publish_batch_normalized_events(
        self,
        events: List[NormalizedEvent],
        subject: str = SUBJECT_NORMALIZED_HOSTING,
    ) -> int:
        """
        Publica masivamente una lista de eventos canónicos en NATS JetStream.
        """
        if not events:
            return 0

        if not self._connected or not self.js:
            connected = await self.connect()
            if not connected:
                raise NatsUnavailableError("Servicio NATS JetStream fuera de línea")

        success_count = 0
        for ev in events:
            try:
                event_dict = ev.to_opensearch_doc()
                payload = json.dumps(event_dict, default=str).encode("utf-8")
                headers = {"Nats-Msg-Id": str(ev.event.id)}
                await self.js.publish(
                    subject=subject,
                    payload=payload,
                    headers=headers,
                    timeout=5,
                )
                success_count += 1
            except Exception as err:
                logger.error("Error al publicar evento %s en batch NATS: %s", ev.event.id, err)

        return success_count

    async def publish_raw_batch(
        self,
        batch_id: str,
        payload_bytes: bytes,
        subject: str = SUBJECT_RAW_HOSTING,
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """Publica un lote crudo de logs en NATS JetStream para consumo de los parser workers."""
        headers = {"Nats-Msg-Id": f"batch-{batch_id}"}

        if not self._connected or not self.js:
            connected = await self.connect()
            if not connected:
                raise NatsUnavailableError("Servicio NATS JetStream fuera de línea")

        try:
            ack = await self.js.publish(
                subject=subject,
                payload=payload_bytes,
                headers=headers,
                timeout=10,
            )
            seq = getattr(ack, "seq", getattr(ack, "sequence", 0))
            return True, ack.stream, seq
        except Exception as e:
            raise NatsServiceError(f"Fallo al publicar lote raw {batch_id}: {e}") from e

    async def publish_dlq(
        self,
        payload_dict: Dict[str, Any],
        reason: str,
        subject: str = SUBJECT_DLQ_PARSING,
    ) -> bool:
        """Envía un payload no procesable a la Dead-Letter Queue (DLQ) de NATS."""
        dlq_entry = {
            "dlq_timestamp": datetime.utcnow().isoformat(),
            "reason": reason,
            "payload": payload_dict,
        }
        data = json.dumps(dlq_entry, default=str).encode("utf-8")

        if not self._connected or not self.js:
            await self.connect()

        if self.js:
            try:
                await self.js.publish(subject=subject, payload=data, timeout=5)
                return True
            except Exception as e:
                logger.error("Error al publicar en DLQ: %s", e)
        return False

    async def publish_list_invalidation(
        self,
        tenant_id: str = "global",
        list_type: Optional[str] = None,
        list_name: Optional[str] = None,
        action: str = "update",
        subject: str = SUBJECT_LISTS_INVALIDATED,
    ) -> bool:
        """
        Publica un mensaje de invalidación reactiva de listas de seguridad en NATS.
        """
        payload_dict = {
            "event": "lists.invalidated",
            "tenant_id": tenant_id,
            "list_type": list_type,
            "list_name": list_name,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
        }
        payload = json.dumps(payload_dict, default=str).encode("utf-8")

        if not self._connected or not self.js:
            try:
                await self.connect()
            except Exception:
                pass

        if self.js:
            try:
                await self.js.publish(subject=subject, payload=payload, timeout=5)
                logger.info("Notificación de invalidación de lista enviada a NATS (%s/%s - %s)", list_type, list_name, action)
                return True
            except Exception as e:
                logger.warning("Error al publicar invalidación de lista en NATS: %s", e)
        return False

    async def publish_rule_invalidation(
        self,
        rule_id: Optional[int] = None,
        action: str = "update",
        subject: str = SUBJECT_RULES_INVALIDATED,
    ) -> bool:
        """
        Publica un mensaje de invalidación reactiva de reglas/bindings en NATS.
        """
        payload_dict = {
            "event": "rules.invalidated",
            "rule_id": rule_id,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
        }
        payload = json.dumps(payload_dict, default=str).encode("utf-8")

        if not self._connected or not self.js:
            try:
                await self.connect()
            except Exception:
                pass

        if self.js:
            try:
                await self.js.publish(subject=subject, payload=payload, timeout=5)
                logger.info("Notificación de invalidación de regla enviada a NATS (rule_id=%s - %s)", rule_id, action)
                return True
            except Exception as e:
                logger.warning("Error al publicar invalidación de regla en NATS: %s", e)
        return False

    def notify_invalidation_sync(self, kind: str = "lists", **kwargs) -> None:
        """
        Invalida de forma segura la memoria local e intenta publicar a NATS desde código síncrono.
        """
        # 1. Invalidación local síncrona inmediata
        try:
            if kind == "lists":
                from app.services.security_list_service import SecurityListService
                SecurityListService.get_instance()._last_load = None
            elif kind == "rules":
                from app.services.rule_engine_v2 import RuleEngineV2
                RuleEngineV2.get_instance().invalidate_cache()
        except Exception as e:
            logger.debug("Error en invalidación local síncrona (%s): %s", kind, e)

        # 2. Publicación distribuida a NATS
        if not HAS_NATS:
            return

        import asyncio
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                if kind == "lists":
                    asyncio.create_task(self.publish_list_invalidation(**kwargs))
                else:
                    asyncio.create_task(self.publish_rule_invalidation(**kwargs))
            else:
                temp_loop = asyncio.new_event_loop()
                try:
                    if kind == "lists":
                        temp_loop.run_until_complete(self.publish_list_invalidation(**kwargs))
                    else:
                        temp_loop.run_until_complete(self.publish_rule_invalidation(**kwargs))
                finally:
                    temp_loop.close()
        except Exception as e:
            logger.debug("Error al notificar invalidación síncrona en NATS: %s", e)

    async def start_control_listener(self) -> None:
        """
        Suscribe NATS a los eventos de control para recarga en caliente de memoria local.
        """
        if not self._connected or not self.nc:
            connected = await self.connect()
            if not connected:
                return

        async def _lists_handler(msg):
            try:
                data = json.loads(msg.data.decode("utf-8"))
                logger.info("Recibida invalidación NATS lists.invalidated: %s", data)
                from app.services.security_list_service import SecurityListService
                SecurityListService.get_instance()._last_load = None
            except Exception as e:
                logger.error("Error procesando mensaje NATS lists.invalidated: %s", e)

        async def _rules_handler(msg):
            try:
                data = json.loads(msg.data.decode("utf-8"))
                logger.info("Recibida invalidación NATS rules.invalidated: %s", data)
                from app.services.rule_engine_v2 import RuleEngineV2
                RuleEngineV2.get_instance().invalidate_cache()
            except Exception as e:
                logger.error("Error procesando mensaje NATS rules.invalidated: %s", e)

        try:
            await self.nc.subscribe(SUBJECT_LISTS_INVALIDATED, cb=_lists_handler)
            await self.nc.subscribe(SUBJECT_RULES_INVALIDATED, cb=_rules_handler)
            logger.info("Suscripción activa a eventos de control NATS (%s, %s)", SUBJECT_LISTS_INVALIDATED, SUBJECT_RULES_INVALIDATED)
        except Exception as e:
            logger.warning("No se pudo suscribir a eventos de control NATS: %s", e)

    async def close(self) -> None:
        if self.nc:
            try:
                await self.nc.close()
            except Exception:
                pass
            self._connected = False
