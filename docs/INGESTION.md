# API de Ingesta Stateless v1 - SentinelX SIEM

## 1. Visión General de la Ingesta

La **API Stateless de Ingesta** (`/api/v1/ingest`) es la puerta de entrada de alta velocidad para eventos en SentinelX-SIEM.

### Características Clave:
- **Stateless**: No realiza escrituras síncronas en base de datos PostgreSQL.
- **Validación Estricta**: Valida payloads contra el esquema Pydantic v2 `NormalizedEvent`.
- **Publicación Durable**: Publica directamente en NATS JetStream y responde `202 Accepted` únicamente tras obtener el ACK del broker.
- **Deduplicación Automática**: Asigna la cabecera NATS `Nats-Msg-Id` utilizando el `event.id` para descartar duplicados en la ventana de ingesta.

---

## 2. Endpoints

### 2.1 Ingesta Individual
`POST /api/v1/ingest/event`

**Headers Required**:
```text
X-API-Key: sx_agent_key_xxxxxxxx
Content-Type: application/json
```

**Respuesta Exitosa (202 Accepted)**:
```json
{
  "status": "accepted",
  "event_id": "3b2a1c09-8f4e-4e1a-9f56-01a2b3c4d5e6",
  "tenant_id": "default",
  "stream": "SENTINELX_EVENTS_NORMALIZED",
  "sequence": 1042,
  "timestamp_utc": "2026-08-09T21:10:00.000000+00:00"
}
```

### 2.2 Ingesta por Lotes
`POST /api/v1/ingest/batch`

**Headers Required**:
```text
X-API-Key: sx_agent_key_xxxxxxxx
Content-Type: application/json
```
