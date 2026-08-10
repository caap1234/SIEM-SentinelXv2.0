# Arquitectura e Integración de Threat Hunting (OpenSearch)

## 1. Visión General

La consola de **Threat Hunting** (`/dashboard/hunting`) permite a analistas y operadores SOC realizar investigaciones avanzadas sobre los Data Streams de OpenSearch (`sentinelx-events-*`). Permite búsquedas en tiempo real combinando lenguaje libre KQL / Lucene con filtros estructurados de ECS.

---

## 2. Endpoints Backend (`app/routers/hunting.py`)

- **`GET /api/v1/hunting/search`**:
  - Parámetros: `q` (consulta libre), `source_ip`, `destination_ip`, `hostname`, `username`, `dataset`, `severity`, `parser`, `rule_id`, `start_date`, `end_date`, `limit`, `offset`.
  - **Aislamiento Multitenant Inviolable**: Inyecta automáticamente el filtro `{"term": {"tenant.id": ctx.tenant_id}}`. El usuario no puede alterar el `tenant_id`.
  - **Permiso Requerido**: `ingest.read`

- **`GET /api/v1/hunting/event/{id}`**:
  - Recupera el detalle canónico ECS de un evento normalizado específico.
  - Verifica que el evento pertenezca al `tenant_id` autenticado.
  - **Permiso Requerido**: `ingest.read`

---

## 3. Integración Alertas -> Threat Hunting -> Evidencia MinIO S3

```text
[Alerta Detectada] ---> Click "Investigar eventos relacionados"
                               |
                               v
                  [/dashboard/hunting?rule_id=...&source_ip=...]
                               |
                               v
                  [Threat Hunting UI - OpenSearch Data Streams]
                               |
                               v
                  [Click "Ver detalle" -> Modal ECS JSON]
                               |
                               v
                  [Click "Explorar Evidencia MinIO S3"]
                               |
                               v
                  [/dashboard/evidence?object_key=...]
```
