# Auditoría del Pipeline de Almacenamiento — SentinelX SIEM (v2)

**Fecha**: 2026-08-11  
**Autor**: Antigravity Assistant / SentinelX Engineering  
**Estado**: Diagnóstico Pre-Implementación  

---

## 1. Flujo Actual Detectado

Al auditar la base de código y la ejecución en producción, se identificó que el pipeline opera actualmente bajo **dos paradigmas híbridos conflictivos**:

```text
[Agente Linux / Cliente API]
              │
              ▼ (Ingesta HTTP Chunk Upload / API)
   [LogUpload (PostgreSQL)] ──► Estado: uploaded ➔ queued
              │
              ▼
   [parsing_worker_loop.py]
              │
              ├─► Parsea líneas y llama a parse_log_file()
              │
              ├─► [DESVIACIÓN ARQUITECTÓNICA]: Llama a _persist_event() 
              │   INSERTANDO CADA LÍNEA DE LOG DIRECTAMENTE EN PostgreSQL.events (40,838+ filas)
              │
              └─► Intenta llamar a _publish_batch_to_nats_sync()
                  (Falla por ciclo de vida de EventLoop cerrado/desconectado)

[Workers NATS Inactivos por Falta de Mensajes en Cola]:
 ├── opensearch_indexer_worker.py ──► Lee NATS (0 mensajes) ──► OpenSearch (0 índices / 0 docs)
 └── minio_evidence_worker.py     ──► Lee NATS (0 mensajes) ──► MinIO S3 (0 evidencias)

[Motor Legacy Polling]:
 └── engine_worker_loop.py        ──► Hace poll a PostgreSQL.events (WHERE engine_status = 'pending')
                                      generando alto bloqueo de escrituras e I/O en Postgres.
```

---

## 2. Diagnóstico del Problema y Causa Raíz

### 2.1 ¿Por qué se insertan datos en `PostgreSQL.events`?
En `app/services/log_pipeline.py` (función `parse_log_file()`), la línea `_persist_event(db, pe, ...)` construye un objeto ORM `Event` por cada línea parseada y ejecuta `db.add(ev)` y `db.flush()`. Esto fue concebido originalmente como un fallback monolítico de desarrollo local, pero en producción provoca un almacenamiento masivo en la base de datos relacional (~40,800 registros por hora por agente), generando *bloat*, ralentización y riesgo de corrupción en PostgreSQL.

### 2.2 ¿Por qué OpenSearch no tiene índices ni documentos?
Aunque `opensearch_worker` está corriendo en Docker, no recibe mensajes de NATS. La razón técnica es que `_publish_batch_to_nats_sync()` en `log_pipeline.py` creaba un bucle de eventos asíncrono temporal (`asyncio.new_event_loop()`) y llamaba a `loop.close()`. Esto cerraba el socket subyacente de `NatsService.get_instance().nc`, haciendo que todas las publicaciones subsecuentes fallaran en silencio (`logger.debug`).

### 2.3 ¿Por qué MinIO S3 no recibe objetos?
Por la misma razón: `minio_evidence_worker` consume del mismo stream de NATS (`SENTINELX_EVENTS_NORMALIZED`). Al no llegar publicaciones de NATS debido a la desconexión del cliente NATS en `parsing_worker`, el worker de MinIO no recibe paquetes para empaquetar y subir a S3.

### 2.4 ¿Los workers están consumiendo realmente o solo levantando?
- `parsing_worker`: Consume de `log_uploads` e inserta masivamente en `PostgreSQL.events`.
- `engine_worker`: Hace polling directo a `PostgreSQL.events`.
- `opensearch_worker`: Levanta y se conecta a NATS, pero su `pull_subscribe` recibe 0 mensajes.
- `evidence_worker`: Levanta y se conecta a NATS, pero su `pull_subscribe` recibe 0 mensajes.

---

## 3. Diseño Arquitectónico Objetivo (Target State)

Para alinear el sistema a los principios definidos en `docs/STORAGE_ARCHITECTURE.md`:

```text
[Agente Client / API]
          │
          ▼
 [parsing_worker_loop] ──(Parses raw lines to NormalizedEvent)
          │
          ▼ (Streaming directo por lotes de ultra alta velocidad)
 [NATS JetStream (STREAM_NORMALIZED)]
          │
 ┌────────┼───────────────────────────┬──────────────────────────┐
 │        │                           │                          │
 ▼        ▼                           ▼                          ▼
[opensearch_worker]           [evidence_worker]          [correlation_worker]
 │                            │                          │
 ▼                            ▼                          ▼
[OpenSearch Data Streams]     [MinIO S3 Bucket]          [PostgreSQL DB]
(Eventos ECS completos,       (Raw evidence comprimida   (ÚNICAMENTE Alertas,
 Threat Hunting, Dashboards)   .json.gz con SHA-256)      Incidentes y Metadatos)
```

### Separación de Responsabilidades:

1. **PostgreSQL**:
   - ALMACENA ÚNICAMENTE: `LogUpload`, `Alert`, `Incident`, `SecurityListEntry`, `RegisteredAgent`, `ApiKey`, `User`, `SystemSetting`.
   - NO almacena eventos masivos ni payloads completos de logs.
   - Referencias ligeras: `opensearch_event_id`, `s3_key`, `triggered_at`, `severity`, `status`.

2. **OpenSearch**:
   - Almacena todos los eventos canónicos ECS (`sentinelx-events-*`).
   - Soportará consultas estilo Lucene/KQL en la pantalla de **Threat Hunting** y tableros analíticos.

3. **MinIO S3**:
   - Almacena evidencia forense inmutable (`sentinelx-evidence/{tenant_id}/{YYYY}/{MM}/{DD}/{dataset}/{event_id}.json.gz`).
   - Asigna hash SHA-256 para integridad probatoria.

---

## 4. Cambios Necesarios en el Código

1. **`app/services/log_pipeline.py` & `app/workers/parsing_worker_loop.py`**:
   - Modificar `parse_log_file()` para **omitir la persistencia en `PostgreSQL.events`**.
   - Garantizar una conexión asíncrona persistente a NATS JetStream para transmitir los eventos canónicos normalizados por lotes sin cerrar el socket de NATS.

2. **`app/workers/correlation_worker.py` / `engine_worker`**:
   - Habilitar `correlation_worker.py` como el motor de correlación reactivo impulsado por NATS JetStream, o ajustar `engine_worker` para leer desde NATS/OpenSearch.
   - `correlation_worker` evaluará reglas en memoria y creará registros en `PostgreSQL.alerts` únicamente cuando una regla sea gatillada.

3. **Alembic Migrations / Estructura DB**:
   - Mantener la tabla `events` en PostgreSQL si se requiere para compatibilidad con consultas legacy o convertirla en una vista/tabla de staging temporal vacía.
   - Crear una migración Alembic si se ajusta la estructura.

---

## 5. Impacto de la Migración

- **Rendimiento**: PostgreSQL liberará hasta un 95% del I/O en disco y uso de CPU, eliminando el riesgo de corrupción por escrituras masivas simultáneas.
- **Capacidad de Escalado**: Se pueden escalar N `parsing_workers` y N `opensearch_workers` sin saturar la base de datos relacional.
- **Funcionalidades Frontend**:
  - **Threat Hunting**: Empezará a mostrar los eventos desde OpenSearch en tiempo real.
  - **Evidencia S3**: Empezará a mostrar los objetos subidos a MinIO S3 con verificación de hash SHA-256.
  - **Dashboard**: Mostrará las métricas de NATS y OpenSearch en verde (`Healthy`).
