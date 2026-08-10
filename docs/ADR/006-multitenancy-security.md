# ADR 006: Aislamiento Multitenant Estricto y RBAC Granular en la Capa API

- **Estado**: Aceptado
- **Fecha**: 2026-08-10
- **Autores**: Arquitecto Principal de Software & Especialista DevSecOps / SIEM

---

## 1. Contexto y Problema

En un entorno de hosting compartido donde múltiples clientes (tenants) gestionan cientos o miles de servidores Linux con cPanel/DirectAdmin, es crítico garantizar que:
1. Ningún cliente pueda acceder o visualizar datos, logs, alertas ni evidencia perteneciente a otro tenant.
2. Ningún usuario pueda suplantar el `tenant_id` mediante parámetros HTTP o solicitudes JSON modificadas.
3. Las claves API de los agentes no se almacenen en texto plano en la base de datos relacional.

---

## 2. Decisión Adoptada

Se implementa una **Arquitectura de Aislamiento Multitenant y RBAC Granular de 4 Niveles**:

1. **Resolución Inviolable del Contexto de Tenant (`AuthContext`)**:
   - El `tenant_id` se resuelve **exclusivamente** desde las credenciales validadas (token JWT del panel o hash de `X-API-Key` del agente en PostgreSQL).
   - Se ignora cualquier valor de `tenant_id` enviado arbitrariamente en el cuerpo o consulta HTTP del cliente.

2. **Seguridad de API Keys de Agentes (`agent_api_keys`)**:
   - Almacenamiento seguro en PostgreSQL mediante firmas **SHA-256** (`key_hash`).
   - Prefijo estándar `sx_live_` y soporte para revocación inmediata y fechas de expiración.

3. **Filtrado Obligatorio en Motores de Búsqueda y Almacenamiento**:
   - **OpenSearch**: Método `search_events()` inyecta obligatoriamente el filtro `{"term": {"tenant.id": tenant_id}}`.
   - **MinIO S3**: Método `retrieve_and_verify_evidence_for_tenant()` valida que la ruta del objeto comience estrictamente con `{tenant_id}/`.

4. **Matriz RBAC Granular (`require_permission`)**:
   - Evaluación declarativa de permisos en endpoints mediante dependencias FastAPI (ej. `require_permission("alerts.manage")`).
   - Retorno estricto de `401 Unauthorized` (sin credenciales) y `403 Forbidden` (credenciales válidas pero permiso denegado).

---

## 3. Consecuencias

- **Seguridad**: Cero riesgo de fuga de datos entre tenants (cross-tenant data leakage).
- **Auditoría**: Todo intento de acceso no autorizado registra una entrada en `audit_logs` con `status="failure"`.
