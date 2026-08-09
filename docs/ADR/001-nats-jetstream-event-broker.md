# ADR 001: Selección de NATS JetStream como Bus de Eventos Persistente

- **Estado**: Aceptado
- **Fecha**: 2026-08-09
- **Autores**: Arquitecto Principal de Software & Equipo DevSecOps

---

## 1. Contexto y Problema

La arquitectura inicial de SentinelX-SIEM utilizaba la base de datos transaccional PostgreSQL como cola de ingesta mediante la tabla `log_uploads` y consultas con bloqueos `FOR UPDATE SKIP LOCKED`.

Bajo volúmenes de ingesta superiores a 200 eventos por segundo (EPS), esta estrategia generaba:
- Competencia masiva por cerrojos (lock contention) en PostgreSQL.
- Degradación severa del I/O de la base de datos.
- Imposibilidad de escalar horizontalmente el plano de ingesta independientemente del plano de almacenamiento transaccional.

Se requiere un motor de mensajería/streaming desacoplado, altamente disponible, persistente y con garantías de entrega durables (*at-least-once*).

---

## 2. Opciones Evaluadas

### Opción A: NATS JetStream (SELECCIONADA)
- **Ventajas**:
  - Binario único sin dependencias de JVM (Java) ni ZooKeeper/KRaft.
  - Footprint de memoria extraordinariamente bajo (~30 MB en reposo).
  - Rendimiento superior a 100,000 msg/s por nodo en hardware estándar.
  - Soporte nativo de persistencia basada en disco por stream (`file` storage).
  - Deduplicación nativa mediante la cabecera `Nats-Msg-Id` con ventana de tiempo configurable (`duplicate_window`).
  - Consumidores durables con ACK explícito y Dead-Letter Queue (DLQ).
- **Desventajas**:
  - Ecosistema de herramientas de administración más pequeño comparado con Kafka.

### Opción B: Redpanda (Kafka Compatible)
- **Ventajas**:
  - Compatible 100% con la API de Apache Kafka sin ZooKeeper/JVM (escrito en C++ con Seastar).
  - Excelente throughput de streaming.
- **Desventajas**:
  - Mayor consumo de memoria y CPU comparado con NATS (requiere pre-asignación de cores y RAM).

### Opción C: RabbitMQ / Redis Streams
- **Desventajas**:
  - Redis Streams presenta riesgo de pérdida si la memoria RAM colapsa bajo picos masivos.
  - RabbitMQ añade complejidad para patrones de streaming persistente ordenado a gran escala.

---

## 3. Decisión Adoptada

Se adopta **NATS JetStream** como el bus de eventos persistente oficial para **SentinelX-SIEM**.

### Topología de Streams Aprobada:
1. `SENTINELX_INGEST_RAW`: Buffer de lotes crudos recibidos desde agentes (`sentinelx.ingest.raw.*`, retención: 7 días).
2. `SENTINELX_EVENTS_NORMALIZED`: Stream principal de eventos canónicos normalizados `NormalizedEvent` (`sentinelx.events.normalized.*`, retención: 7 días).
3. `SENTINELX_DLQ`: Dead-Letter Queue para eventos corruptos o no parseables (`sentinelx.dlq.*`, retención: 30 días).
4. `SENTINELX_METRICS`: Stream de métricas de host e internas (`sentinelx.metrics.*`, retención: 3 días).

---

## 4. Consecuencias

- **Positivas**:
  - Desacoplamiento total entre la API de ingesta HTTP/mTLS y los consumidores/workers.
  - Latencia de ingesta p95 < 5 ms tras eliminar la escritura directa en PostgreSQL durante la ingesta.
  - Resiliencia garantizada con deduplicación por `event.id`.
- **Mitigaciones**:
  - Los consumidores deben implementar semántica *at-least-once* y tolerar duplicados fuera de la ventana de deduplicación de 2 minutos.
