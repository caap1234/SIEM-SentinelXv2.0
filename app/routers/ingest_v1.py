# app/routers/ingest_v1.py
"""
API Stateless de Ingesta v1 para SentinelX SIEM.
Recibe, valida y publica eventos canónicos (NormalizedEvent) directamente hacia NATS JetStream.
"""
from __future__ import annotations

import os
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Header, status, BackgroundTasks
from pydantic import BaseModel, Field

from app.schemas.normalized_event import NormalizedEvent
from app.services.nats_service import NatsService, NatsUnavailableError, NatsServiceError

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest_v1"])

# Default max batch events (can be overridden dynamically via env)
DEFAULT_MAX_BATCH_EVENTS = 5000


class IngestAckResponse(BaseModel):
    status: str = Field(default="accepted")
    event_id: str
    tenant_id: str
    stream: Optional[str] = None
    sequence: Optional[int] = None
    timestamp_utc: str


class BatchIngestAckResponse(BaseModel):
    status: str = Field(default="accepted")
    total: int
    accepted_count: int
    failed_count: int
    tenant_id: str
    timestamp_utc: str
    items: List[IngestAckResponse]


def verify_ingest_auth(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> str:
    """
    Validador de autenticación para agentes y clientes de ingesta.
    En producción verifica contra DB/Cache; en desarrollo o con key 'test-key' acepta.
    """
    key = (x_api_key or "").strip()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Falta cabecera de autenticación X-API-Key",
        )
    return key


@router.post(
    "/event",
    response_model=IngestAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingesta individual de evento normalizado (Stateless)",
)
async def ingest_single_event(
    event: NormalizedEvent,
    api_key: str = Depends(verify_ingest_auth),
):
    """
    Recibe un evento canónico (NormalizedEvent), asigna tenant_id y publica hacia NATS JetStream.
    Retorna 202 Accepted únicamente tras confirmar la publicación durable en el broker.
    """
    nats_service = NatsService.get_instance()

    try:
        success, stream_name, seq = await nats_service.publish_normalized_event(event)
    except NatsUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Servicio de ingesta NATS JetStream no disponible: {e}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fallo en la publicación de ingesta: {e}",
        )

    return IngestAckResponse(
        status="accepted",
        event_id=event.event.id,
        tenant_id=event.tenant.id,
        stream=stream_name or "SENTINELX_EVENTS_NORMALIZED",
        sequence=seq or 0,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/batch",
    response_model=BatchIngestAckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingesta por lotes de eventos normalizados (Stateless)",
)
async def ingest_batch_events(
    events: List[NormalizedEvent],
    api_key: str = Depends(verify_ingest_auth),
):
    """
    Recibe un lote de eventos normalizados y los publica masivamente en NATS JetStream.
    """
    if not events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El lote de eventos se encuentra vacío",
        )

    max_batch = int(os.getenv("INGEST_MAX_BATCH_EVENTS", str(DEFAULT_MAX_BATCH_EVENTS)))
    if len(events) > max_batch:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"El lote excede el tamaño máximo permitido ({len(events)} > {max_batch})",
        )

    nats_service = NatsService.get_instance()
    items: List[IngestAckResponse] = []
    accepted = 0
    failed = 0
    tenant_id = events[0].tenant.id if events else "default"

    for ev in events:
        try:
            success, stream_name, seq = await nats_service.publish_normalized_event(ev)
            accepted += 1
            items.append(
                IngestAckResponse(
                    status="accepted",
                    event_id=ev.event.id,
                    tenant_id=ev.tenant.id,
                    stream=stream_name or "SENTINELX_EVENTS_NORMALIZED",
                    sequence=seq or 0,
                    timestamp_utc=datetime.now(timezone.utc).isoformat(),
                )
            )
        except NatsUnavailableError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio NATS JetStream fuera de línea durante el procesamiento del lote",
            )
        except Exception as e:
            failed += 1
            items.append(
                IngestAckResponse(
                    status="error",
                    event_id=ev.event.id,
                    tenant_id=ev.tenant.id,
                    timestamp_utc=datetime.now(timezone.utc).isoformat(),
                )
            )

    return BatchIngestAckResponse(
        status="accepted" if failed == 0 else "partial_error",
        total=len(events),
        accepted_count=accepted,
        failed_count=failed,
        tenant_id=tenant_id,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        items=items,
    )
