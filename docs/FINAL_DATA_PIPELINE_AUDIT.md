# Auditoría Final del Pipeline de Datos — SentinelX SIEM

**Fecha**: 2026-08-11  
**Documento**: `docs/FINAL_DATA_PIPELINE_AUDIT.md`  
**Estado**: Diagnóstico Final & Recomendaciones Técnicas  

---

## 1. Flujo de Datos Arquitectónico Objetivo (Target State)

```text
 [Agente Linux / Cliente API]
              │
              ▼ (HTTP Chunk Upload / POST /logs/ingest)
   [LogUpload (PostgreSQL)] ──► Estado: queued
              │
              ▼
   [parsing_worker_loop] ──► Parsea líneas a NormalizedEvent
              │
              ▼ (Batch Stream high-throughput)
   [NATS JetStream (STREAM_NORMALIZED)]
              │
 ┌────────────┼───────────────────────────┬──────────────────────────┐
 │            │                           │                          │
 ▼            ▼                           ▼                          ▼
[opensearch_worker]           [evidence_worker]          [correlation_worker]
 │                            │                          │
 ▼                            ▼                          ▼
[OpenSearch Data Streams]     [MinIO S3 Bucket]          [PostgreSQL DB]
(sentinelx-events-*)          (sentinelx-evidence/)      (ÚNICAMENTE Alertas,
- Threat Hunting              - Evidencia comprimida     Incidentes, Entidades,
- Dashboards                  - Firma SHA-256            Metadatos SOC)
- Consultas KQL
```

---

## 2. Diagnóstico por Componente

### 2.1 Agent & Spool Ingest (`sentinelx-agent.sh`)
- **Estado**: 🟢 **Funciona**.
- **Diagnóstico de `final_flush_failed`**: Ocurría cuando un chunk antiguo en el carrete del agente devolvía un `HTTP 400 Bad Request` o tiempo de espera, provocando que `flush_spool()` abortara antes de enviar el resto de la cola.
- **Solución Implementada**: En el commit `96f1ba3`, se añadió el auto-descarte de trabajos con respuesta HTTP 400/422, permitiendo que la cola continúe enviándose limpiamente.

### 2.2 Motor de Búsqueda y Threat Hunting (OpenSearch)
- **Estado**: 🟢 **Funciona (20,082+ documentos)**.
- **Límite de 10,000 Eventos en UI**:
  - **Causa Raíz**: OpenSearch/Elasticsearch limita por defecto `hits.total.value` a 10,000 para optimizar rendimiento de cómputo a menos que se solicite el conteo exacto.
  - **Recomendación**: Pasar el parámetro `"track_total_hits": true` en la consulta `search_events()` de `OpenSearchClient` para que la UI muestre el conteo real exacto (e.g. `20,082`) manteniendo la paginación eficiente de resultados (`from`/`size`).

### 2.3 Evidencia Forense Inmutable (MinIO S3)
- **Estado**: 🟢 **Funciona**.
- **Comprobación**: `evidence_worker` consume los eventos de NATS JetStream, empaqueta los archivos `.json.gz` con su correspondiente firma SHA-256 e inyecta la evidencia en la ruta jerárquica `default/YYYY/MM/DD/dataset/event_id.json.gz`.

### 2.4 Motor de Detección y Alertas (`correlation_worker`)
- **Estado**: 🟡 **Pendiente de Activación en Docker**.
- **Causa Raíz**: El servicio `correlation_worker` no estaba registrado en `docker-compose.example.yml`. El `engine_worker` anterior buscaba eventos en PostgreSQL `events` (que ahora tiene 0 filas por diseño).
- **Recomendación**: Agregar `correlation_worker` a `docker-compose.yml` y añadir el bloque `if __name__ == "__main__":` en `app/workers/correlation_worker.py` para procesar alertas en tiempo real desde NATS JetStream.

### 2.5 Tablas de Almacenamiento Relacional (`rawlogs_*` y `events_*`)
- **Estado**: ℹ️ **Residuo de Arquitectura Monolítica Anterior**.
- **Evaluación**: Ningún componente activo (Threat Hunting, Evidencia S3, Dashboards) lee de las tablas relacionales de eventos `rawlogs_YYYY_MM_DD` o `events_YYYY_MM_DD`.
- **Recomendación**: Mantenerlas temporalmente sin modificar hasta validar el entorno de producción en verde y programar su purga en una migración Alembic limpia.

---

## 3. Matriz de Componentes y Acciones Recomendadas

| Componente | Estado Actual | Acción Necesaria | Impacto |
|---|---|---|---|
| **Threat Hunting Count** | Muestra max 10,000 | Inyectar `track_total_hits: true` en `OpenSearchClient.search_events()` | La UI mostrará el total exacto de documentos en OpenSearch (20,082+). |
| **Correlation Worker** | No iniciado en Compose | Agregar servicio `correlation_worker` a Compose y bloque `__main__` | Se generarán alertas relacionales en PostgreSQL a partir de reglas reactivas. |
| **Agente Spool** | Con descarga 400 | Aplicar binario `sentinelx-agent.sh` con auto-purge 400 | El carrete local se vaciará continuamente. |
| **Tablas legacy `rawlogs_*`** | Inactivas en Postgres | Documentadas para futura purga | 0 impacto operacional. |
