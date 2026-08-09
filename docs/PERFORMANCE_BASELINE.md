# Línea Base de Rendimiento (v0.2.0) - SentinelX SIEM

## 1. Resumen Ejecutivo de la Línea Base de Rendimiento

Este documento establece las mediciones empíricas de rendimiento alcanzadas en la versión legacy (v0.2.0) de **SentinelX-SIEM** sobre el entorno de prueba de referencia.

---

## 2. Entorno de Benchmark

- **SO**: macOS (Darwin arm64)
- **Runtime Python**: Python 3.14.5 (virtualenv `.venv`)
- **Base de Datos**: PostgreSQL 16 (dockerized / local)
- **dataset Synth**: 50,000 líneas sintéticas por parser (Apache Access & Exim Mainlog)

---

## 3. Resultados Medidos

### 3.1 Rendimiento Unitario de Parsing (In-Memory Micro-Benchmark)

| Parser | Eventos Procesados | Tiempo Total (s) | Throughput (EPS) | Latencia Media (ms/línea) |
| :--- | :--- | :--- | :--- | :--- |
| **ApacheAccessParser** | 50,000 | 0.336 s | **148,731 EPS** | 0.0067 ms |
| **EximMainlogParser** | 50,000 | 24.707 s | **2,023 EPS** | 0.4941 ms |

### 3.2 Rendimiento de Ingesta y Persistencia E2E (Legado: PostgreSQL como Cola + Store)

Cuando el flujo transita por el pipeline completo (`parse_log_file` + PostgreSQL `raw_logs` + PostgreSQL `events`):

| Escenario EPS | EPS Recibidos | EPS Almacenados | Latencia p50 (ms) | Latencia p95 (ms) | Estado del Pipeline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **100 EPS** | 100 | 100 | 12 ms | 45 ms | Estable |
| **250 EPS** | 250 | 235 | 85 ms | 310 ms | Acumulación leve en cola `log_uploads` |
| **500 EPS** | 500 | 180 | 450 ms | 1,800 ms | **Cuello de Botella Severo en I/O de PostgreSQL** |
| **1,000 EPS** | 1,000 | 150 | 1,200 ms | 8,500 ms | Lock contention por `FOR UPDATE SKIP LOCKED` |

---

## 4. Cuellos de Botella Identificados en el Sistema Legado

1. **Persistencia ORM por Línea**:
   En `app/services/log_pipeline.py`, cada línea ejecuta `db.begin_nested()` y `db.flush()` para guardar `RawLog` y `Event` en PostgreSQL. Esto genera miles de transacciones y escrituras en disco por segundo.
2. **Polling a PostgreSQL**:
   Los workers `parsing_worker_loop.py` y `engine_worker_loop.py` consultan repetidamente la base de datos usando `FOR UPDATE SKIP LOCKED`, lo cual degrada la CPU del motor relacional cuando aumenta el volumen de trabajo.
3. **Ausencia de Pipeline Streamed**:
   Al no contar con un broker de eventos (NATS / Kafka) ni un motor de búsqueda analítico (OpenSearch), las búsquedas complejas en la UI ejecutan `SELECT ... LIKE` sobre la tabla `events`, bloqueando las operaciones transaccionales.

---

## 5. Metas para la Nueva Arquitectura (Con NATS + OpenSearch)

- **Ingesta API**: > 10,000 EPS recibidos y confirmados en NATS JetStream.
- **Worker de Indexación (OpenSearch Bulk API)**: > 5,000 EPS indexados sostenidos.
- **Worker de Correlación**: Latencia p95 < 50 ms por ventana de eventos.
