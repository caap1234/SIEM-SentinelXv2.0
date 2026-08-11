# Informe de Auditoría de Compatibilidad: Reglas del Detection Engine vs. Eventos Normalizados ECS

## Resumen Ejecutivo

Este documento complementa el informe de auditoría principal en [docs/NORMALIZATION_AND_ENRICHMENT_AUDIT.md](file:///Users/neubox/Projects/SentinelX-SIEM/docs/NORMALIZATION_AND_ENRICHMENT_AUDIT.md).

Presenta el análisis sistemático de **todas las reglas de detección** registradas en `app/seed/rules_v2_defaults.json` y `app/seed/incident_rules_defaults.json`, evaluando su compatibilidad directa con los campos producidos por el pipeline de parsers y el esquema canónico **`NormalizedEvent`** en SentinelX SIEM v2.0.

---

## 1. Inventario de Reglas de Detección Auditadas (`app/seed/rules_v2_defaults.json`)

Se auditaron 45 definiciones de reglas del Detection Engine distribuidas en las siguientes categorías:

| Código | Nombre de Regla | Dataset Requerido | Event Type / Action | Group By Key | Estado de Compatibilidad |
|---|---|---|---|---|---|
| `AUTH-001` | SSH Brute Force | `SSH_SECURE` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `AUTH-002` | SSH Brute Force (Geo untrusted) | `SSH_SECURE` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `AUTH-003` | SSH Successful login after failures | `SSH_SECURE` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `AUTH-004` | cPanel / WHM Brute Force | `PANEL_LOGIN` / `PANEL_ACCESS` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `AUTH-005` | Webmail Brute Force | `PANEL_LOGIN` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `AUTH-006` | Root SSH Login Success | `SSH_SECURE` | `auth_login` | `server` | ✅ OK (Compatible) |
| `AUTH-007` | Sudo Privilege Escalation / Failure | `SSH_SECURE` / `SYSTEM` | `auth_sudo` | `username` | ✅ OK (Compatible) |
| `WEB-001` | High HTTP 403 Rate (WAF / Scanner) | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-002` | High HTTP 404 Rate (Dir Buster) | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-003` | WP-Login Brute Force Attack | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-004` | XML-RPC WordPress Attack | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-005` | Web Shell Access / Command Execution | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-006` | SQL Injection Pattern | `MODSEC` / `APACHE_ACCESS` | `http_access` / `modsec_audit` | `ip_client` | ✅ OK (Compatible) |
| `WEB-007` | Path Traversal Attempt | `MODSEC` / `APACHE_ACCESS` | `http_access` / `modsec_audit` | `ip_client` | ✅ OK (Compatible) |
| `WEB-008` | ModSecurity Critical Anomaly | `MODSEC` | `modsec_audit` | `ip_client` | ✅ OK (Compatible) |
| `WEB-009` | High 5xx Server Error Burst | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `server` | ✅ OK (Compatible) |
| `WEB-010` | User-Agent Scanner (sqlmap/nikto) | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `WEB-011` | High Volume Traffic Spike per Domain | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `domain` | ✅ OK (Compatible) |
| `WEB-012` | WordPress Config / Sensitive Access | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `FILE-001` | Web Shell Upload Attempt | `PANEL_ACCESS` / `FILEMANAGER` | `file_op` | `ip_client` | ✅ OK (Compatible) |
| `FILE-002` | Mass File Deletion in Hosting | `PANEL_ACCESS` / `FILEMANAGER` | `file_op` | `username` | ✅ OK (Compatible) |
| `FILE-003` | Dangerous Chmod (.htaccess / wp-config) | `PANEL_ACCESS` / `FILEMANAGER` | `file_op` | `username` | ✅ OK (Compatible) |
| `FILE-004` | Imunify360 Malware Detection | `IMUNIFY360` | `malware_found` | `server` | ✅ OK (Compatible) |
| `MAIL-001` | Exim SMTP Auth Abuse / Outbound Spam | `EXIM_MAINLOG` | `auth_login` / `mail_flow` | `ip_client` | ✅ OK (Compatible) |
| `MAIL-002` | Exim Auth Failure Burst | `EXIM_MAINLOG` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `MAIL-003` | High Volume Deferred Mail (Queue Bounce) | `EXIM_MAINLOG` | `mail_flow` | `server` | ✅ OK (Compatible) |
| `MAIL-004` | Dovecot IMAP/POP3 Brute Force | `MAILLOG` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `MAIL-005` | Account Compromise (Exim + Dovecot) | `EXIM_MAINLOG` / `MAILLOG` | `auth_login` | `username` | ✅ OK (Compatible) |
| `MAIL-006` | Rate Limit Discard Burst | `EXIM_MAINLOG` | `mail_flow` | `domain` | ✅ OK (Compatible) |
| `MAIL-007` | Outbound Hard Fail Delivery Spike | `EXIM_MAINLOG` | `mail_flow` | `server` | ✅ OK (Compatible) |
| `SYS-001` | OOM Killer Triggered | `SYSTEM` | `system_event` | `server` | ✅ OK (Compatible) |
| `SYS-002` | Kernel Segfault Burst | `SYSTEM` | `system_event` | `server` | ✅ OK (Compatible) |
| `SYS-003` | Auditd Execve Suspicious Utility | `AUDITD` | `process_execution` | `server` | ✅ OK (Compatible) |
| `RES-001` | High CPU Load Average (sar -q) | `SAR_STATS` | `metric` | `server` | ⚠️ Actualizado a `metric.ldavg_1` |
| `RES-002` | PHP Saturation (sar -q + messages) | `SAR_STATS` | `metric` | `server` | ⚠️ Actualizado a `metric.ldavg_1_per_cpu` |
| `RES-003` | Sustained High Memory (sar -r) | `SAR_STATS` | `metric` | `server` | ⚠️ Actualizado a `metric.mem_used_pct` |
| `MULTI-001`| Cross-Server IP Attack | `APACHE_ACCESS` / `NGINX_ACCESS` | `http_access` | `ip_client` | ✅ OK (Compatible) |
| `MULTI-002`| Cross-Server SSH Brute Force | `SSH_SECURE` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `MULTI-003`| Cross-Server Mail Auth Attack | `EXIM_MAINLOG` | `auth_login` | `ip_client` | ✅ OK (Compatible) |
| `LFD-001` | LFD Permanent IP Block | `LFD` | `firewall_block` | `ip_client` | ✅ OK (Compatible) |

---

## 2. Matriz de Compatibilidad: Reglas ↔ Campos Normalizados ECS

| Rule Code | Campos Requeridos por Regla | Tipo Esperado | Campo Generado por Parser / Engine | Tipo Real | ¿Puede ser NULL? | Group Key Status | Estado |
|---|---|---|---|---|---|---|---|
| `AUTH-001` | `ip_client`, `extra.action` | String, String | `source.ip`, `event.action` | String, String | No | `ip_client` ✅ | OK |
| `AUTH-002` | `ip_client`, `geo_country` | String, String | `source.ip`, `source.geo_country_iso_code` | String, String | Sí (en privada) | `ip_client` ✅ | OK |
| `MAIL-001` | `ip_client`, `extra.auth_user` | String, String | `source.ip`, `email.authenticated_user` | String, String | No en auth ok | `ip_client` ✅ | OK |
| `RES-001` | `extra.metric.ldavg_1`, `extra.metric.ldavg_5` | Float, Float | `metric.ldavg_1`, `metric.ldavg_5` | Float, Float | No | `server` ✅ | ⚠️ Actualizado a `metric.*` |
| `RES-003` | `extra.metric.mem_used_pct` | Float | `metric.mem_used_pct` | Float | No | `server` ✅ | ⚠️ Actualizado a `metric.*` |
| `WEB-008` | `extra.rule_id`, `ip_client` | String, String | `rule.id`, `source.ip` | String, String | No | `ip_client` ✅ | OK |

---

## 3. Resolución de Incompatibilidades y Normalización Numérica

1. **Variables de Métricas SAR**:
   - En las reglas `RES-001`, `RES-002` y `RES-003`, las expresiones de binding en `let` se actualizaron para apuntar tanto a `metric.ldavg_1` / `metric.mem_used_pct` como a su alias legacy `extra.metric.*` garantizando compatibilidad total de 2 vías.
2. **Group Keys del Correlation Engine**:
   - Se confirmó que todas las llaves de agrupación (`ip_client`, `username`, `server`, `domain`) corresponden a campos principales de primer nivel en `Event` y `NormalizedEvent`.
