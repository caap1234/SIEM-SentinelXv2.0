# Operación y Configuración de NATS JetStream - SentinelX SIEM

## 1. Topología de Streams y Subjects

| Stream | Subjects Mapeados | Retención | Almacenamiento | Propósito |
| :--- | :--- | :--- | :--- | :--- |
| `SENTINELX_INGEST_RAW` | `sentinelx.ingest.raw.*` | 7 Días | Disco (`file`) | Ingesta cruda enviada por agentes antes de parseo. |
| `SENTINELX_EVENTS_NORMALIZED` | `sentinelx.events.normalized.*` | 7 Días | Disco (`file`) | Stream principal de eventos normalizados `NormalizedEvent`. |
| `SENTINELX_DLQ` | `sentinelx.dlq.*` | 30 Días | Disco (`file`) | Dead-Letter Queue para líneas corruptas o fallos de indexación. |
| `SENTINELX_METRICS` | `sentinelx.metrics.*` | 3 Días | Disco (`file`) | Métricas de sistema y recursos del host. |

---

## 2. Consumidores Durables (Durable Consumers)

1. `parser_worker_group`: Escucha `sentinelx.ingest.raw.*` y emite hacia `sentinelx.events.normalized.*`.
2. `opensearch_indexer_group`: Escucha `sentinelx.events.normalized.*` e indexa en OpenSearch Data Streams por lotes.
3. `correlation_engine_group`: Escucha `sentinelx.events.normalized.*` para evaluación de reglas de detección en tiempo real.

---

## 3. Comandos de Diagnóstico y Operación

```bash
# Ver estado del clúster NATS JetStream
curl http://localhost:8222/jsz?streams=true

# Ver información de healthcheck
curl http://localhost:8222/healthz
```
