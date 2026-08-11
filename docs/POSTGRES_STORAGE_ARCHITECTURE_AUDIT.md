# Auditoría de Arquitectura del Almacenamiento PostgreSQL — SentinelX SIEM

**Fecha**: 2026-08-11  
**Documento**: `docs/POSTGRES_STORAGE_ARCHITECTURE_AUDIT.md`  
**Estado**: Auditoría de Tablas Relacionales & Estrategia de Depuración  

---

## 1. Propósito de PostgreSQL en la Arquitectura Decoupled (SIEM 2.0)

La arquitectura oficial de SentinelX SIEM establece un desacoplamiento estricto de las capas de persistencia para garantizar escalabilidad masiva sin saturación de E/S relacional:

* **PostgreSQL (Metadatos SOC Transaccionales)**: Almacena exclusivamente datos relacionales de control: `users`, `tenants`, `api_keys`, `rules_v2`, `alerts`, `incidents_v2`, `entities` y `log_uploads` (referencias a S3/OpenSearch).
* **OpenSearch (Eventos Canónicos ECS)**: Almacena eventos canónicos completos, logs estructurados y realiza búsquedas analíticas de Threat Hunting.
* **MinIO S3 (Evidencia Forense Cruda)**: Almacena archivos de log crudos comprimidos (`.json.gz`) firmados con hash SHA-256 para cumplimiento legal e inspección forense.

---

## 2. Análisis de Tablas Existentes en PostgreSQL

Actualmente, la base de datos PostgreSQL contiene los siguientes grupos de tablas:

### 2.1 Tablas Activas de Producción (Metadatos SOC)
| Grupo de Tablas | Tablas Específicas | Propósito | Estado |
|---|---|---|---|
| **Seguridad y Acceso** | `users`, `rbac_roles`, `rbac_permissions`, `api_keys`, `agent_api_keys` | Autenticación, RBAC y llaves API de agentes. | 🟢 **Activa** |
| **Multitenancy y Agentes** | `tenants`, `agents`, `system_settings` | Gestión de clientes/tenants y agentes Linux registrados. | 🟢 **Activa** |
| **Detección y SOC** | `rules_v2`, `rule_state_v2`, `alerts`, `incidents_v2`, `entities` | Reglas de seguridad, ciclo de vida de Alertas, Incidentes y Entidades. | 🟢 **Activa** |
| **Control de Ingesta** | `log_uploads`, `service_checkpoints` | Seguimiento de lotes de carga y referencias de offsets. | 🟢 **Activa** |

---

### 2.2 Tablas Particionadas de Eventos y Logs Crudos (`events_*` y `rawlogs_*`)
| Patrón de Tabla | Origen / Quién la creó | Componente que escribe | Componente que consulta | Recomendación |
|---|---|---|---|---|
| `events_YYYY_MM_DD` | Migración Alembic `7015555057f7` y triggers automáticos | Prototipo monolítico inicial (`log_pipeline.py`) | Ninguno (Inactivo) | 🟡 **Candidata a Eliminación Futura** |
| `rawlogs_YYYY_MM_DD` | Migración Alembic `7015555057f7` y triggers automáticos | Prototipo monolítico inicial (`raw_policy.py`) | Ninguno (Inactivo) | 🟡 **Candidata a Eliminación Futura** |

---

## 3. Respuestas a las Preguntas de Auditoría

1. **¿Quién creó las tablas `rawlogs_YYYY_MM_DD`?**
   Fueron creadas por la migración de Alembic `7015555057f7_partition_events_and_rawlogs_by_day.py` y por triggers automáticos de particionado PostgreSQL durante la primera fase de desarrollo del prototipo monolítico.

2. **¿Qué componente escribe en `rawlogs_*` y `events_*`?**
   Anteriormente escribía la función síncrona `log_pipeline.py`. En la arquitectura actual (`PERSIST_EVENTS_TO_POSTGRES=0`), el pipeline escribe en NATS JetStream, OpenSearch y MinIO S3. **Ningún worker actual escribe en las tablas `rawlogs_*` ni `events_*`**.

3. **¿Qué componente las consulta?**
   **Ningún componente las consulta**. Ni las vistas de Threat Hunting, ni los Dashboards SOC, ni el Motor de Correlación, ni el Explorador de Evidencia consultan estas tablas (Threat Hunting consulta OpenSearch y la Evidencia consulta MinIO).

4. **¿Son necesarias actualmente?**
   **NO**. Son estructuras legacy. La información analítica reside en OpenSearch y los registros crudos están archivados en MinIO S3.

5. **¿Existe duplicidad con OpenSearch?**
   **SÍ**. Si se guardaran en Postgres, existiría una duplicidad del 100% de datos masivos que saturaría el almacenamiento en disco y la RAM de PostgreSQL.

---

## 4. Estrategia y Plan de Migración / Limpieza Futura

### Política de Seguridad:
> [!IMPORTANT]
> **No eliminar tablas de forma inmediata**. Las tablas actuales consumen únicamente 48 kB cada una (espacio de catálogo SQL vacío) y no interfieren con el rendimiento del sistema.

### Plan de Depuración Programado (Fase Posterior):
1. **Paso 1 (Auditoría de Datos)**: Verificar con `SELECT count(*) FROM rawlogs_YYYY_MM_DD` si contienen registros históricos del prototipo inicial.
2. **Paso 2 (Migración Alembic de Depreciación)**: Crear una migración Alembic que ejecute el borrado controlado (`DROP TABLE IF EXISTS public.rawlogs CASCADE; DROP TABLE IF EXISTS public.events CASCADE;`).
3. **Impacto Estimado**: **Zero Impacto Operacional**. Liberación de espacio en catálogo `pg_class` y simplificación del esquema en PostgreSQL.
