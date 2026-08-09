# Contrato Canónico de Eventos - SentinelX SIEM (v1.0.0)

## 1. Visión General del Esquema

El **Esquema Canónico de SentinelX-SIEM** (`sentinelx-ecs` v1.0.0) estandariza todos los eventos ingeridos desde servidores Linux, cPanel/WHM, DirectAdmin, Exim, Dovecot, Apache, Nginx, ModSecurity, Imunify360, CSF/LFD, cPHulk, auditd, journald y firewalls perimetrales (WatchGuard, Corero).

Basado conceptualmente en **Elastic Common Schema (ECS)** y la taxonomía **OCSF**, garantiza que un campo como la IP de origen se represente **siempre** como `source.ip`, eliminando variantes como `client_ip`, `src_ip` o `remote_addr`.

---

## 2. Estructura de Campos Canónicos

### Campos Raíz y Metadatos del Esquema
- `@timestamp`: Fecha y hora del evento en formato UTC ISO 8601 (Obligatorio).
- `schema.name`: `"sentinelx-ecs"`
- `schema.version`: `"1.0.0"`

### Clasificación del Evento (`event.*`)
- `event.id`: UUIDv4 único global.
- `event.kind`: `event` | `alert` | `metric` | `state`.
- `event.category`: Lista de categorías ECS (e.g., `["mail"]`, `["web", "security"]`).
- `event.type`: Lista de tipos ECS (e.g., `["access"]`, `["allowed"]`, `["denied"]`).
- `event.action`: Nombre de la acción específica (e.g., `smtp_auth_success`, `http_post_xmlrpc`).
- `event.outcome`: `success` | `failure` | `unknown`.
- `event.severity`: Escala numérica de 0 (info) a 100 (crítico).
- `event.risk_score`: Puntuación de riesgo acumulado (0.0 a 100.0).
- `event.dataset`: Nombre del dataset (e.g., `exim.mainlog`, `modsecurity.audit`).
- `event.original`: Copia de la línea cruda de log o evidencia original.

### Aislamiento y Multitenancy (`tenant.*` y `customer.*`)
- `tenant.id`: Identificador obligatorio del Tenant (Unidad de aislamiento principal).
- `customer.customer_id`: Identificador del cliente comercial de hosting.
- `customer.reseller_id`: Identificador del revendedor (Reseller).
- `customer.account_id`: Nombre de la cuenta cPanel / DirectAdmin.
- `customer.domain_name`: Dominio de hosting asociado.

### Infraestructura y Origen (`host.*`, `agent.*`, `service.*`)
- `host.id` / `host.name` / `host.hostname` / `host.ip` / `host.os_name` / `host.os_version`
- `agent.id` / `agent.name` / `agent.version`
- `service.name` (e.g., `exim`, `dovecot`, `apache`, `nginx`, `modsecurity`, `csf`, `cphulk`) / `service.type`

### Red y Protocolos (`source.*`, `destination.*`, `network.*`)
- `source.ip` / `source.port` / `source.geo_country_iso_code` / `source.as_number` / `source.as_organization_name`
- `destination.ip` / `destination.port`
- `network.transport` (`tcp`, `udp`) / `network.protocol` (`http`, `smtp`, `imap`, `ssh`, `dns`)

### Entidades Específicas
- **Usuario** (`user.*`): `user.id`, `user.name`, `user.domain`
- **Proceso** (`process.*`): `process.pid`, `process.name`, `process.executable`, `process.command_line`
- **Archivo** (`file.*`): `file.path`, `file.name`, `file.extension`, `file.size`, `file.hash_sha256`
- **URL y HTTP** (`url.*`, `http.*`): `url.original`, `url.path`, `http.method`, `http.status_code`, `http.referrer`
- **Correo SMTP/IMAP** (`email.*`): `email.from_address`, `email.to_address`, `email.subject`, `email.message_id`, `email.queue_id`, `email.authenticated_user`
- **Regla de Detección** (`rule.*`): `rule.id`, `rule.name`, `rule.category`, `rule.version`
- **Log Origen** (`log.*`): `log.level`, `log.file_path`, `log.offset`, `log.original`
