# Administración del SOC y Auditoría Administrativa SentinelX

## 1. Visión General

La arquitectura de administración del SOC en SentinelX establece las bases para una operación segura, auditada y multitenant.

---

## 2. Eventos de Auditoría Registrados (`audit_logs`)

Todas las acciones administrativas sensibles quedan registradas inmutablemente en la base de datos PostgreSQL mediante el servicio `log_audit_event`:

| Acción | Recurso | Detalles Registrados |
| :--- | :--- | :--- |
| `API_KEY_CREATE` | `api_keys` | Servidor asignado, nombre de la clave, Hash SHA-256 generado (nunca el texto claro). |
| `API_KEY_REVOKE` | `api_keys` | ID de la clave revocada y fecha de desactivación. |
| `RULE_UPDATE` | `rules_v2` | `rule_id`, campo modificado, valor anterior y nuevo valor. |
| `AGENT_REGISTER` | `registered_agents` | Hostname, IP de origen, versión del agente y OS. |

---

## 3. Preparación para `/dashboard/auditoria`

Las entradas registradas en `audit_logs` contienen `tenant_id`, `user_id`, `username`, `action`, `resource`, `ip_address`, `status` y el documento `details` JSONB. Esto sienta las bases para la vista de auditoría administrativa SOC.
