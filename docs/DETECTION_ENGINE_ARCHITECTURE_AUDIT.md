# Auditoría Arquitectónica del Motor de Detección y Correlación — SentinelX SIEM

**Fecha**: 2026-08-11  
**Documento**: `docs/DETECTION_ENGINE_ARCHITECTURE_AUDIT.md`  
**Estado**: Auditoría Técnica & Propuesta de Rediseño Distribuido  

---

## 1. Diagnóstico del Problema Actual

Durante las pruebas de estrés con la regla `RULE_MAIL_SMTP_AUTH_BRUTEFORCE` (umbral: 50 eventos de autenticación fallida en 300 segundos), se identificó un fallo de diseño fundamental en el escalado del `CorrelationEngine`:

### Causa Raíz:
1. **Memoria Local Fragmentada**: La clase `CorrelationEngine` almacenaba las ventanas deslizantes (`SlidingWindowBucket`) en un `dict` local en la memoria RAM del proceso Python (`self.windows = defaultdict(...)`).
2. **Distribución en Cola por JetStream**: Al escalar el worker a `N` instancias (`correlation_worker-1`, `correlation_worker-2`), NATS JetStream distribuye los mensajes entre los workers mediante un grupo de consumo (*Queue Group*).
3. **Fragmentación del Umbral**: Si se envían 100 eventos, el worker 1 recibe ~50 eventos y el worker 2 recibe ~50 eventos. Sin embargo, debido a variaciones en la velocidad de consumo, el worker 1 almacena en su RAM local 48 eventos y el worker 2 almacena 52 eventos. Si se envían 55 eventos, la cuenta se divide en ~27 y ~28 por worker. Ningún worker alcanza el umbral de 50 en su memoria RAM aislada.
4. **Pérdida de Estado en Reinicios**: Si un contenedor `correlation_worker` se reinicia, toda la memoria deslizante se borra a cero (`clear`), perdiendo la secuencia de ataques en curso.

---

## 2. Evaluación de Opciones Arquitectónicas para SIEM Distribuido

| Criterio | Opción A: NATS Key-Value (KV) Store (Recomendada) | Opción B: Particionado por Tópico (Hash-Routing) | Opción C: Almacén Redis Externo |
|---|---|---|---|
| **Mecanismo** | Utiliza la característica nativa de NATS JetStream `js.create_key_value(bucket="sentinelx_correlation_windows")` | Publica eventos en `sentinelx.events.normalized.{hash(ip)}` y asigna workers fijos por partición | Introduce un contenedor `redis` para guardar las listas de timestamps por `bucket_key` |
| **Escalabilidad** | 🟢 **Excelente** (N workers leen/escriben concurrentemente en NATS KV) | 🟡 **Limitada** (Diferentes reglas agrupan por distintos campos: `source.ip`, `user.name`, `host.name`) | 🟢 **Alta** |
| **Resiliencia** | 🟢 **Inmune a reinicios** (NATS JetStream persiste el KV bucket en disco) | 🔴 **Vulnerable a fallos de nodo** | 🟢 **Alta** |
| **Complejidad / Ops** | 🟢 **Zero Ops** (Utiliza el contenedor NATS que ya está corriendo en Docker) | 🟡 **Alta** (Requiere re-enrutador de tópicos) | 🔴 **Requiere gestionar Redis** |
| **Latencia** | ⚡ **< 1 ms** (NATS KV opera en RAM con persistencia asíncrona) | ⚡ **< 1 ms** | ⚡ **< 1 ms** |

---

## 3. Arquitectura Seleccionada: Engine de Correlación Distribuido con NATS KV

```text
       [Agente Linux / Cliente API]
                    │
                    ▼ (Ingesta HTTP Chunk Upload)
         [LogUpload (PostgreSQL)]
                    │
                    ▼
         [parsing_worker_loop] ──► Parsea a NormalizedEvent
                    │
                    ▼ (Stream NATS JetStream: SENTINELX_EVENTS_NORMALIZED)
      ┌─────────────┼─────────────────────────────┬────────────────────────────┐
      │             │                             │                            │
      ▼             ▼                             ▼                            ▼
[opensearch_worker] [evidence_worker]   [correlation_worker-1]       [correlation_worker-2]
  (OpenSearch)      (MinIO S3)                    │                            │
                                                  └──────────────┬─────────────┘
                                                                 │ (Lee/Escribe estado compartido)
                                                                 ▼
                                                  ┌──────────────────────────────┐
                                                  │   NATS JetStream KV Store    │
                                                  │ "sentinelx_correlation_kv"   │
                                                  │                              │
                                                  │ Claves con TTL automático:   │
                                                  │ tenant:rule_id:group_key    │
                                                  └──────────────┬───────────────┘
                                                                 │ (Si bucket.count >= threshold)
                                                                 ▼
                                                  ┌──────────────────────────────┐
                                                  │  PostgreSQL (Tabla alerts)   │
                                                  └──────────────────────────────┘
```

### Principios del Rediseño:
1. **Estado de Ventana Compartido**: El estado de cada ventana `(tenant_id, rule_id, group_key)` se persiste de forma distribuida en NATS Key-Value Store (`sentinelx_correlation_kv`).
2. **TTL Automático por Regla**: La clave NATS KV expira automáticamente cuando vence la ventana temporal (`time_window_seconds`).
3. **Consistencia N-Workers**: Cualquier número de `correlation_worker` (1, 2, 4, 10) consulta y actualiza la misma clave en NATS KV, permitiendo que la suma acumulada de eventos alcance el umbral exacto de la regla.
4. **Resiliencia ante Reinicios**: Si un worker se cae, el siguiente worker retoma la ventana desde el punto exacto en NATS KV sin perder contadores.

---

## 4. Trazabilidad del Flujo Completo End-to-End

| Etapa | Componente | Evento / Acción | Verificación |
|---|---|---|---|
| **1. Ingesta** | Agente Linux | Escanea logs y hace POST chunk gzip | HTTP 200/201 en backend. LogUpload `queued`. |
| **2. Parseo** | `parsing_worker` | Parsea líneas a `NormalizedEvent` | Publica lote en NATS `STREAM_NORMALIZED`. |
| **3. Threat Hunting** | `opensearch_worker` | Consume de NATS JetStream | Indexa en OpenSearch Data Stream `sentinelx-events-*`. |
| **4. Evidencia** | `evidence_worker` | Consume de NATS JetStream | Sube `.json.gz` con SHA-256 a MinIO S3. |
| **5. Detección** | `correlation_worker` (N Workers) | Consume de NATS JetStream y consulta NATS KV | Actualiza la ventana en NATS KV. Si `count >= threshold`, inserta `Alert` en PostgreSQL `alerts`. |
| **6. Visibilidad SOC** | Dashboard & Alert UI | Consulta PostgreSQL `alerts` y OpenSearch | Muestra la alerta en tiempo real en la consola SOC. |

---

## 5. Plan de Implementación y Verificación

1. **`app/services/correlation_engine.py`**:
   - Integrar `NatsService` KV bucket (`sentinelx_correlation_kv`).
   - Implementar persistencia y recuperación de `SlidingWindowBucket` desde NATS KV.
   - Proveer fallback en memoria local si NATS KV no estuviera inicializado.
2. **Prueba Automatizada en `tests/unit/test_correlation_engine.py`**:
   - Verificar que el motor de correlación distribuido acumula eventos y dispara alertas relacionales al alcanzar el umbral exacto.
