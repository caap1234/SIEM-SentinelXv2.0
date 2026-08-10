# Auditoría Completa del Dashboard Existente y Mapeo SOC

## 1. Evaluación de Componentes Existentes

| Componente | Archivo | Estado Actual | Fuente de Datos Actual | Estado Deseado (SOC) |
| :--- | :--- | :--- | :--- | :--- |
| **KPIs Principales** | `StatsCard.astro` / `index.astro` | Parcialmente funcional | `GET /dashboard/kpis` | `GET /api/v1/dashboard/summary` (Eventos recibidos, procesados, indexados, alertas activas, incidentes, agentes). |
| **Estado del Sistema** | `SystemStatusCard.astro` | Intenta consumir `/dashboard/system-status` | Mock / Desconectado | `GET /api/v1/dashboard/summary` -> `system_health` (FastAPI, NATS, OpenSearch, MinIO, PostgreSQL). |
| **Actividad de Eventos** | `ActivityChart.astro` | Gráfica estática o con datos parciales | `GET /dashboard/activity` | `GET /api/v1/dashboard/activity` (Serie temporal de eventos por minuto / 24h). |
| **Incidentes / Alertas** | `RecentEventsCard.astro` | Consume `/dashboard/incidents/recent` | Parcial | `GET /api/v1/dashboard/alerts/recent` (Alertas críticas ordenadas por severidad con regla disparada). |
| **Entidades / IPs** | `SuspiciousIPsCard.astro` | Mock / Parcial | `GET /dashboard/suspicious-ips` | Enlazado a `entities` con score de riesgo >= 30. |
| **Monitoreo de Agentes** | *Inexistente* | Sin widget dedicado | N/A | Nuevo widget: `AgentStatusWidget` alimentado por `GET /api/v1/dashboard/agents/status`. |

---

## 2. Endpoints Backend Disponibles y Faltantes

### Endpoints Disponibles en Backend:
- `/api/v1/ingest/event`, `/api/v1/ingest/batch`: Ingesta de eventos.
- `/api/v2/alerts`: CRUD de alertas relacionales.
- `/api/v2/incidents`: CRUD de incidentes relacionales.
- `/auth/login`, `/auth/me`: Autenticación.

### Endpoints SOC Faltantes que se Implementarán en FastAPI (`app/routers/dashboard.py`):
1. **`GET /api/v1/dashboard/summary`**:
   - Retorna la salud de servicios (`system_health`), total de eventos recibidos, procesados, indexados, alertas activas, incidentes abiertos y agentes online.
2. **`GET /api/v1/dashboard/activity`**:
   - Retorna la serie de tiempo de actividad por hora (24h).
3. **`GET /api/v1/dashboard/alerts/recent`**:
   - Retorna las últimas alertas críticas asociadas a reglas de hosting (Exim, Dovecot, WordPress, SSH, ModSec, Imunify360).
4. **`GET /api/v1/dashboard/agents/status`**:
   - Retorna el resumen de estado de agentes Linux (`healthy`, `delayed`, `offline`), heartbeat, uso de memoria, CPU y tamaño del spool local.
