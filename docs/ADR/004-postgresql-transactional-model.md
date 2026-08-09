# ADR 004: Separación de PostgreSQL como Base de Datos Transaccional y Multitenant

- **Estado**: Aceptado
- **Fecha**: 2026-08-09
- **Autores**: Arquitecto Principal de Software & Especialista SIEM

---

## 1. Contexto y Problema

En las versiones iniciales de SentinelX-SIEM, la base de datos PostgreSQL cumplía un triple propósito no escalable:
1. Cola de ingesta (`log_uploads` con consultas `FOR UPDATE SKIP LOCKED`).
2. Almacén de logs crudos y analíticos (`rawlogs` y `events`).
3. Base de datos transaccional para usuarios, alertas y reglas.

Bajo volúmenes de ingesta masiva (cPanel, DirectAdmin, Exim), la concurrencia de escrituras de logs en PostgreSQL degradaba la respuesta del SIEM.

---

## 2. Decisión Adoptada

Se efectúa la **separación estricta de responsabilidades**:

1. **PostgreSQL Transaccional**:
   - Reservado **exclusivamente** para metadatos de control: `tenants`, `users`, `roles`, `permissions`, `registered_agents`, `audit_logs`, `alerts`, `incidents`, `rules_v2` y `system_settings`.
   - **Desuso Progresivo**: Las tablas de logs históricos crudos (`rawlogs` y `events` en SQL) dejan de ser la vía primaria de ingesta y búsqueda.

2. **OpenSearch**:
   - Motor primario para búsqueda analítica, agregaciones y filtros en tiempo real sobre eventos normalizados (`NormalizedEvent`).

3. **MinIO (S3)**:
   - Repositorio oficial de evidencia cruda inmutable con compresión `gzip` y firmas **SHA-256**.

4. **Multitenancy Estricto (`tenant_id`)**:
   - Todas las entidades de control relacionales incluyen la clave foránea `tenant_id` vinculada a la tabla `tenants(id)`.

---

## 3. Consecuencias

- Cero competencia por bloqueos (lock contention) en PostgreSQL durante picos de tráfico de logs.
- Control de acceso RBAC granular (`admin`, `analyst`, `operator`, `viewer`).
- Registro completo de auditoría forense administrativa en la tabla `audit_logs`.
