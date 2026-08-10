# Arquitectura del Dashboard SOC en Tiempo Real

## 1. Visión General

El **Dashboard SOC en Tiempo Real** de SentinelX SIEM transforma la vista ejecutiva estática en una consola activa de operaciones de seguridad (SOC) para entornos de hosting. Se alimenta directamente de la API v1 (`/api/v1/dashboard/*`) respaldada por PostgreSQL, NATS JetStream, OpenSearch Data Streams y el motor de correlación reactivo.

---

## 2. Endpoints Backend (`app/routers/dashboard.py`)

1. **`GET /api/v1/dashboard/summary`**:
   - Resumen de estado del clúster (salud de API, NATS, OpenSearch, MinIO, PostgreSQL).
   - KPIs de eventos recibidos, procesados e indexados.
   - Contadores de alertas activas y agentes Linux online.
   - **Permiso Requerido**: `ingest.read`

2. **`GET /api/v1/dashboard/activity`**:
   - Serie de tiempo de 24 horas con agrupación horaria de volumen de eventos y alertas disparadas.
   - **Permiso Requerido**: `ingest.read`

3. **`GET /api/v1/dashboard/alerts/recent`**:
   - Lista de las últimas 10 alertas de alta severidad disparadas por el motor de correlación (WordPress bruteforce, Exim spam, Imunify360 webshell, SSH bruteforce).
   - **Permiso Requerido**: `alerts.read`

4. **`GET /api/v1/dashboard/agents/status`**:
   - Estado de salud (`healthy`, `delayed`, `offline`), heartbeat, versión, consumo de memoria/CPU y eventos en spool local de los agentes.
   - **Permiso Requerido**: `ingest.read`

---

## 3. Estrategia de Tiempo Real y Polling

- **Polling Configurable**: Los widgets del dashboard refrescan su estado automáticamente mediante peticiones asíncronas periódicas cada **15 a 30 segundos** utilizando `setInterval()`.
- **Desacoplamiento UI**: La arquitectura de cliente `front/src/lib/dashboard.js` y `front/src/lib/api.js` está preparada para reemplazar el mecanismo de Polling por conexiones WebSocket / Server-Sent Events (SSE) en fases posteriores sin modificar el renderizado de componentes Astro.

---

## 4. Aislamiento Multitenant y Seguridad

- Todos los endpoints de la API SOC resuelven obligatoriamente el contexto de la solicitud mediante `AuthContext`.
- Las métricas y alertas retornadas se filtran estrictamente por el `tenant_id` autenticado.
