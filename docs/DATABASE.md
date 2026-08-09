# Esquema Relacional Transaccional - PostgreSQL (SentinelX SIEM)

## 1. Mapeo de Entidades Transaccionales

| Tabla | Clave Primaria | Propósito | Indexación |
| :--- | :--- | :--- | :--- |
| `tenants` | `id` (VARCHAR 64) | Unidad principal de aislamiento multitenant. | `ix_tenants_status` |
| `roles` | `id` (INT) | Roles RBAC (`admin`, `analyst`, `operator`, `viewer`). | Unique `name` |
| `permissions` | `id` (INT) | Permisos granulares (`alerts.manage`, etc.). | Unique `name` |
| `role_permissions` | `(role_id, permission_id)` | Matriz de permisos por rol. | Foreign Keys |
| `registered_agents` | `id` (UUID) | Control de salud y estado de agentes Linux. | `ix_registered_agents_hostname`, `tenant_id` |
| `audit_logs` | `id` (UUID) | Auditoría administrativa y de seguridad. | `ix_audit_logs_timestamp_utc`, `tenant_id` |

---

## 2. Migraciones Alembic

```bash
# Ver versión actual de migración
alembic current

# Aplicar migraciones hacia la última versión (head)
alembic upgrade head

# Revertir una migración (downgrade)
alembic downgrade -1
```
