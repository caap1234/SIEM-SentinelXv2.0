# Reporte de Diagnóstico y Causa Raíz del Pipeline de Ingesta y Almacenamiento

**Fecha**: 2026-08-11  
**Documento**: `docs/STORAGE_PIPELINE_DEBUG_REPORT.md`  
**Estado**: DIAGNÓSTICO COMPLETO (PRE-IMPLEMENTACIÓN)  

---

## 1. Causa Raíz Identificada 🎯

En la optimización de ingesta desacoplada previa, los eventos dejaron de escribirse en `PostgreSQL.events` (comportamiento correcto esperado para evitar *bloat* relacional). Sin embargo, tampoco llegaron a **OpenSearch** ni a **MinIO S3**.

Al auditar la trazabilidad interna del código en `app/services/log_pipeline.py`:

```python
# CÓDIGO AFECTADO (Líneas 427-432 en parse_log_file):
try:
    tenant_str = str(log.tenant_id or "default") if log else "default"
    norm_ev = pe.to_normalized_event(tenant_id=tenant_str)
    nats_batch_events.append(norm_ev)
except Exception as nats_err:
    logger.debug("NATS event conversion notice: %s", nats_err)
```

### El Fallo:
1. El modelo SQLAlchemy `LogUpload` (tabla `log_uploads`) **NO tiene la columna `tenant_id`** (la relación se mantiene mediante `api_key.tenant_id` o `extra_meta`).
2. Al ejecutar `log.tenant_id`, Python genera una excepción silenciosa **`AttributeError: 'LogUpload' object has no attribute 'tenant_id'`**.
3. El bloque `except Exception as nats_err:` capturaba silenciosamente la excepción por cada línea parseada.
4. Como resultado, **`nats_batch_events` NUNCA acumuló ningún evento** (`nats_batch_events` siempre permaneció vacío `[]`).
5. **Cero mensajes se publicaron hacia NATS JetStream**, por lo que `opensearch_indexer_worker` y `minio_evidence_worker` recibieron 0 eventos para procesar.

---

## 2. Matriz de Estado por Componente

| Componente | Estado Detectado | Causa del Estado |
|---|---|---|
| **Agente Linux (`svgt187`)** | 🟢 **Funciona** | Sube los archivos correctamente hacia `POST /logs/ingest`. |
| **`parsing_worker`** | 🟡 **Parcial** | Procesa los archivos `.gz`, pero la conversión al evento canónico fallaba en `log.tenant_id`. |
| **NATS JetStream** | 🔴 **0 Mensajes** | No recibía eventos de `log_pipeline.py` por el `AttributeError` silencioso. |
| **`opensearch_worker`** | 🟡 **Standby** | Listo y conectado a NATS, pero la cola `SENTINELX_EVENTS_NORMALIZED` tenía 0 mensajes. |
| **`evidence_worker`** | 🟡 **Standby** | Listo y conectado a NATS, pero la cola `SENTINELX_EVENTS_NORMALIZED` tenía 0 mensajes. |
| **OpenSearch Cluster** | 🔴 **0 Índices / 0 Docs** | No recibía escrituras bulk al no haber mensajes en NATS. |
| **MinIO S3 Evidence** | 🔴 **0 Objetos** | No recibía payloads `.json.gz` al no haber mensajes en NATS. |
| **PostgreSQL DB** | 🟢 **0 Bloat (OK)** | Libre de escrituras masivas de eventos conforme a la arquitectura desacoplada. |

---

## 3. Corrección Diseñada

1. **Resolución Segura de `tenant_id` en `log_pipeline.py`**:
   Remplazar la inspección directa de `log.tenant_id` por una resolución segura a través de la relación de la API Key o los metadatos de carga:
   ```python
   tenant_str = "default"
   if log:
       if getattr(log, "api_key", None) and getattr(log.api_key, "tenant_id", None):
           tenant_str = str(log.api_key.tenant_id)
       elif isinstance(log.extra_meta, dict) and log.extra_meta.get("tenant_id"):
           tenant_str = str(log.extra_meta["tenant_id"])
   ```

2. **Visibilidad de Errores**:
   Sustituir el captura silenciosa `logger.debug` por un aviso explícito `logger.warning` en caso de fallas de conversión durante el desarrollo.

3. **Pruebas de Integración y Flujo Completo**:
   Crear un test automatizado que verifique que `parse_log_file()` genera y acumula `NormalizedEvent` con tenant válido sin lanzar `AttributeError`.

---

## 4. Impacto de la Corrección

- **Ingesta**: En cuanto se aplique el arreglo, los lotes de eventos serán publicados exitosamente en NATS JetStream.
- **Threat Hunting**: OpenSearch creará inmediatamente los índices `sentinelx-events-default` (o por tenant) mostrando los eventos en la consola.
- **Evidencia S3**: MinIO S3 almacenará los archivos `.json.gz` etiquetados con hash SHA-256 en la ruta `default/YYYY/MM/DD/dataset/event_id.json.gz`.
- **PostgreSQL**: Se mantendrá ligero y rápido (sin registros masivos en `events`).
