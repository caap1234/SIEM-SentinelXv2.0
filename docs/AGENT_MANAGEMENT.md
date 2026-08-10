# Gestión y Telemetría de Agentes Linux en SentinelX SIEM

## 1. Visión General

El módulo de **Gestión de Agentes Linux** (`/dashboard/agentes`) permite auditar la ingesta en tiempo real, conectividad y telemetría de servidores Linux (cPanel/WHM, CloudLinux, AlmaLinux, Ubuntu, RHEL).

> **IMPORTANTE**: El agente es estrictamente de telemetría y recolección de logs. **NO** ejecuta acciones defensivas automáticas, bloqueo de IPs ni comandos remotos en los servidores.

---

## 2. Definición de Estados de Salud

El estado del agente se calcula dinámicamente según la frescura de su último heartbeat:
- **`healthy` (Saludable)**: Reporte telemétrico recibido en los últimos 5 minutos (&lt; 300s).
- **`delayed` (Retrasado)**: Reporte telemétrico recibido entre 5 y 30 minutos atrás (300s - 1800s).
- **`offline` (Desconectado)**: Sin reporte telemétrico por más de 30 minutos (&gt; 1800s) o sin check-in previo.

---

## 3. Endpoints Backend (`app/routers/agents.py`)

- **`GET /api/v1/agents`**:
  - Parámetros: `status_filter` (`healthy` \| `delayed` \| `offline`), `hostname`, `limit`, `offset`.
  - **Aislamiento por Tenant**: Filtra obligatoriamente por el `tenant_id` de las credenciales del usuario.
  - **Permiso Requerido**: `agents.manage`

- **`GET /api/v1/agents/{id}`**:
  - Muestra metadata completa, versión del agente, kernel, IP registrada y eventos de telemetría recientes.
  - **Permiso Requerido**: `agents.manage`

- **`POST /api/v1/agents/heartbeat`**:
  - Endpoint utilizado por el agente en Linux para enviar su check-in telemétrico.
  - **Permiso Requerido**: `ingest.read` / API Key de Agente válida.
