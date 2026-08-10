# Reporte de Corrección SOC, Evidencia y Consistencia de Datos — SentinelX SIEM

Este documento detalla los resultados, correcciones de consistencia y verificaciones ejecutadas para alinear el comportamiento de **SentinelX SIEM** con el modelo SOC de operación real.

---

## 1. Problemas Encontrados y Correcciones Realizadas

### 1.1 Módulo Evidencia y Logs Originales (MinIO S3)
- **Cambio**: Se reestructuró la interfaz y concepto de "Evidencia Forense" a **"Evidencia y Logs Originales"** ([evidence.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/evidence.astro)).
- **Detalles**: Se ocultó la carga manual de archivos independientes. MinIO/S3 se consolidó como el almacén inmutable de logs recibidos y JSON ECS normalizados (`tenant/year/month/day/dataset/event-id.json.gz`).
- **Verificación**: Cada objeto muestra metadatos de Tenant, Dataset, Fecha de Ingesta, Hash SHA-256 y Estado de Integridad (`VERIFICADA`).

### 1.2 Flujo de Alertas y Resolución por Incidente
- **Cambio**: Estandarizados los estados de alertas: `new` / `open` ("Nueva"), `in_investigation` ("En investigación"), `resolved` ("Resuelta"), `false_positive` ("Falso positivo") y `closed_by_incident` ("Cerrada por incidente") en [alerts.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/alerts.py) e [incidents_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/incidents_v2.py).
- **Regla de Negocio**:
  - Las alertas **nunca se eliminan**.
  - Al resolver un incidente, sus alertas vinculadas pasan automáticamente a `closed_by_incident`.
  - Las **entidades (IPs, usuarios, hostnames) conservan su ciclo de vida independiente** (ya no se cierran en cascada al cerrar el incidente).

### 1.3 Centro de Investigación de Incidentes, Timeline SOC & Notas
- **Cambio**: Se enriqueció la ficha del incidente ([incidents_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/incidents_v2.py) y [incidentes.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/incidentes.astro)).
- **Nuevas Funcionalidades**:
  - **Timeline SOC**: Registro cronológico de hitos (detección de alertas, asociación de entidades, inicio de investigación y cierre).
  - **Notas del Analista**: Formulario y listado persistente (`POST /api/v1/incidents_v2/{id}/notes`) para guardar comentarios de contexto.
  - **Navegación Directa**: Enlaces rápidos hacia *Threat Hunting* (`/dashboard/hunting?q=...`) y *Evidencia MinIO S3* (`/dashboard/evidence`).

### 1.4 Corrección TypeError toLowerCase en Threat Hunting
- **Problema**: Excepción `TypeError: ((intermediate value) || "info").toLowerCase is not a function` en [hunting.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/hunting.astro) cuando `severity` venía como número u objeto desde OpenSearch.
- **Corrección**: Implementada función parseadora defensiva que evalúa números (1..3), cadenas u objetos sin interrumpir el renderizado de la tabla.

### 1.5 Corrección Dashboard & Consistencia de Agentes Linux
- **Dashboard NaN/undefined**: Se ajustó `/api/v1/dashboard/activity` en [dashboard.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/dashboard.py) y los valores por defecto en [ActivityChart.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/components/dashboard/ActivityChart.astro).
- **Consistencia Agentes**: Se reemplazó el valor estático `agents_online: 3` en el resumen del dashboard por el conteo real en PostgreSQL (`RegisteredAgent`) filtrado por `tenant_id` con `last_seen_at < 300s` (< 5 min).

### 1.6 RBAC & Payload JWT
- **Cambio**: En [auth.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/auth.py), los JWT emitidos incluyen `user_id`, `tenant_id`, `role` y `permissions` (mapa de permisos del usuario). El usuario administrador inicial (`INITIAL_ADMIN_EMAIL`) obtiene `role: admin` y acceso total.

---

## 2. Matriz de Verificación de Pruebas

| Validación | Comando / Método | Resultado | Notas |
|---|---|---|---|
| **Backend Unit Tests** | `.venv/bin/pytest --no-header -q` | **96 Passed** (0 Failures) | 100% de la suite pasando en 13.34s |
| **Astro Type Check** | `npm run check` (en `front/`) | **0 Errors, 0 Warnings** | Sin advertencias ni errores en el frontend |
| **Frontend Production Build** | `npm run build` (en `front/`) | **17/17 Pages Built** | Bundle estático compilado en 1.07s |
| **Generación de Datos** | `python scripts/seed_test_data.py` | **Exitoso** | Entidades, alertas, incidente `INC-SEC-01` y evidencia MinIO S3 poblados |

---

## 3. Estado Final

SentinelX SIEM opera con trazabilidad completa de investigación SOC:
`Logs recibidos ➔ Eventos ECS ➔ Alertas ➔ Incidentes ➔ Entidades ➔ Evidencia S3 Inmutable ➔ Timeline & Notas de Analista`.
