# ADR 002: Indexación en OpenSearch mediante Data Streams, Plantillas ECS y Políticas ISM

- **Estado**: Aceptado
- **Fecha**: 2026-08-09
- **Autores**: Arquitecto Principal de Software & Especialista SIEM / DevSecOps

---

## 1. Contexto y Problema

El volumen de eventos ingeridos por SentinelX-SIEM en una empresa de hosting masivo (cPanel, DirectAdmin, Exim, ModSec, Auditd) genera gigabytes o terabytes de logs estructurados diarios.

Se requiere un motor de búsqueda analítico en tiempo real que permita:
- Indexación acelerada por Data Streams append-only.
- Esquema estandarizado compatible con Elastic Common Schema (ECS).
- Ciclo de vida automatizado de índices (ISM) para mover datos entre estados Hot (0-7d), Warm (7-30d) y Delete (90d+).
- Tolerancia a fallos: el motor analítico nunca debe bloquear la ingesta ni la cola de mensajería (NATS JetStream).

---

## 2. Decisiones Adopadas

1. **OpenSearch Data Streams (`sentinelx-events-*`)**:
   - Se utilizan **Data Streams** nativos append-only para evitar la gestión manual de nombres de índices por fecha (`sentinelx-events-2026.08.09`).
   - Cada documento enviado contiene el campo obligatorio `@timestamp` con fecha y hora UTC ISO 8601.

2. **Index Template ECS-Compliant (`sentinelx-events-template`)**:
   - Configura la estructura estricta de tipos de campo: `@timestamp` (`date`), `source.ip` (`ip`), `destination.ip` (`ip`), `http.status_code` (`integer`), `event.severity` (`integer`), `event.risk_score` (`float`).

3. **Política ISM (Index State Management)**:
   - **Hot State (0 a 7 días)**: Escritura y búsqueda activa en SSD rápido.
   - **Warm State (7 a 30 días)**: Índice en modo solo lectura (`read_only`).
   - **Delete State (90+ días)**: Eliminación automática de datos caducados para conservar almacenamiento.

4. **Resiliencia de Indexación y DLQ**:
   - El worker de indexación (`OpenSearchIndexerWorker`) consume de NATS JetStream por lotes.
   - **Si OpenSearch se encuentra indisponible (503 / Timeout)**: El worker NO envía confirmación (ACK) a NATS. NATS JetStream mantiene los mensajes y reintenta con backoff exponencial.
   - **Si un evento individual es rechazado por conflicto de esquema (400 Bad Request)**: El evento es redirigido a la Dead-Letter Queue (DLQ) en NATS (`sentinelx.dlq.indexing`) y confirmado en el stream principal para no bloquear la cola.

---

## 3. Consecuencias

- Desacoplamiento completo: Caídas prolongadas de OpenSearch no provocan pérdida de eventos (NATS JetStream almacena hasta 7 días en spool de disco).
- Búsquedas ultrarrápidas p95 < 20 ms en eventos de seguridad de hosting.
