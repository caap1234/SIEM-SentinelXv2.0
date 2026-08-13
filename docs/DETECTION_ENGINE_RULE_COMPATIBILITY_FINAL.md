# Matriz Definitiva de Compatibilidad de Reglas de Detección ECS v1.0.0

Este documento contiene la auditoría completa e individual de las **57 reglas oficiales** de detección de SentinelX SIEM (`app/seed/rules_v2_defaults.json`), su contrato con el estándar de eventos normalizados **ECS v1.0.0**, y su estado de verificación.

---

## 🏛️ Arquitectura del Motor de Detección Canónico

- **Módulo Núcleo Único**: `app/services/detection_core.py`
- **Motor Canónico**: `app/services/rule_engine_v2.py`
- **Motor Reactivo NATS**: `app/services/correlation_engine.py` (composición directa sobre `RuleEngineV2` / `DetectionCore`)
- **Reprocesamiento Batch**: `app/services/rule_reprocess.py`

---

## 📊 Matriz de Categorías Lógicas de Dataset (`DATASET_CATEGORIES`)

Construida exclusivamente a partir de los `event.dataset` reales producidos por los parsers de ingesta:

| Categoría Lógica | Datasets Reales Soportados |
|---|---|
| `SSH_AUTH` | `system_secure`, `ssh_secure` |
| `MAIL_AUTH` | `maillog_dovecot` |
| `MAIL_FLOW` | `exim_mainlog` |
| `WEB_ACCESS` | `nginx_access`, `apache_access`, `cpanel_access` |
| `WEB_ERROR` | `apache_error`, `wp_error` |
| `WAF` | `modsec` |
| `PANEL` | `cpanel_access`, `panel_access`, `filemanager` |
| `SYSTEM_METRICS` | `sar`, `sar_stats` |
| `SYSTEM_LOGS` | `system`, `auditd` |
| `SECURITY_AGENT` | `lfd`, `imunify360` |

---

## 📋 Matriz de Compatibilidad de las 57 Reglas Oficiales

| ID | Nombre de Regla | Categoría Lógica | Campos Requeridos ECS | Threshold | Window | Group Key | Estado | Cambio Aplicado |
|---|---|---|---|---|---|---|---|---|
| **AUTH-001** | SSH brute force detected (por IP) | `SSH_AUTH` | `event.outcome`, `service.name`, `source.ip` | `fail_count >= 10` | 900s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.action` $\rightarrow$ `event.outcome`, `ip_client` $\rightarrow$ `source.ip` |
| **AUTH-002** | Multiple users from same IP (SSH) | `SSH_AUTH` | `event.outcome`, `service.name`, `source.ip`, `user.name` | `fail_count >= 12 and unique_users >= 5` | 900s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.action` $\rightarrow$ `event.outcome`, `username` $\rightarrow$ `user.name` |
| **AUTH-002** | Multiple users from same IP (Dovecot) | `MAIL_AUTH` | `event.outcome`, `service.name`, `source.ip`, `user.name` | `fail_count >= 12 and unique_users >= 5` | 900s | `host.name\|source.ip` | ✅ Migrada a ECS | Soporta `service.name` `imap` / `pop3` |
| **AUTH-003** | Failed authentication then success (SSH) | `SSH_AUTH` | `service.name`, `source.ip`, `user.name` | `success_count >= 1 and fail_count >= 6` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **AUTH-003** | Failed authentication then success (Dovecot) | `MAIL_AUTH` | `service.name`, `source.ip`, `user.name` | `success_count >= 1 and fail_count >= 6` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | Soporta `service.name` `imap` / `pop3` |
| **AUTH-004** | User attacked from multiple IPs (SSH) | `SSH_AUTH` | `event.outcome`, `service.name`, `source.ip`, `user.name` | `fail_count >= 15 and unique_ips >= 5` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **AUTH-004** | User attacked from multiple IPs (Dovecot) | `MAIL_AUTH` | `event.outcome`, `service.name`, `source.ip`, `user.name` | `fail_count >= 15 and unique_ips >= 5` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **AUTH-005** | Login from unexpected country (SSH) | `SSH_AUTH` | `event.outcome`, `service.name`, `source.geo_country_iso_code` | `success_count >= 1` | 3600s | `host.name\|user.name` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **AUTH-005** | Login from unexpected country (Dovecot) | `MAIL_AUTH` | `event.outcome`, `service.name`, `source.geo_country_iso_code` | `success_count >= 1` | 3600s | `host.name\|user.name` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **AUTH-006** | Privileged login from new IP (SSH) | `SSH_AUTH` | `event.outcome`, `service.name`, `user.name`, `source.ip` | `success_count >= 1` | 3600s | `host.name\|user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **AUTH-007** | cPanel authentication abuse (por IP) | `PANEL` | `panel.area`, `panel.action`, `panel.status`, `source.ip` | `fail_count >= 8` | 900s | `host.name\|source.ip` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **WEB-001** | Path scanning detected (por IP) | `WEB_ACCESS` | `source.ip`, `url.path` | `unique_paths >= 25 and count >= 40` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-002** | XML-RPC anomalous usage detected | `WEB_ACCESS` | `source.ip`, `url.path` | `count >= 30` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-003** | Exploit pattern detected (por IP) | `WEB_ACCESS` | `source.ip`, `url.path` | `count >= 15` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-004** | Access to sensitive files (por IP) | `WEB_ACCESS` | `source.ip`, `url.path` | `count >= 10` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-005** | WordPress login brute force (por IP) | `WEB_ACCESS` | `source.ip`, `url.path` | `fail_count >= 20` | 600s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-006** | High HTTP 4xx error rate (por IP) | `WEB_ACCESS` | `source.ip`, `http.status_code` | `count >= 50` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `http_status` $\rightarrow$ `http.status_code` |
| **WEB-007** | High HTTP 5xx error rate (por domain) | `WEB_ACCESS` | `customer.domain_name`, `http.status_code` | `count >= 100` | 300s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `extra.vhost` $\rightarrow$ `customer.domain_name` |
| **WEB-008** | Webshell / Malicious upload attempts | `WEB_ACCESS` | `source.ip`, `url.path` | `count >= 5` | 600s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.http.path` $\rightarrow$ `url.path` |
| **WEB-009** | High 404 error burst from non-trusted ASN | `WEB_ACCESS` | `source.ip`, `source.as_number`, `http.status_code` | `count >= 80` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.asn.number` $\rightarrow$ `source.as_number` |
| **WEB-010** | Suspected Phishing / Fake login paths | `WEB_ACCESS` | `customer.domain_name`, `url.path` | `count >= 10` | 600s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `extra.vhost` $\rightarrow$ `customer.domain_name` |
| **WEB-011** | High 403 Forbidden burst (directory listing) | `WEB_ACCESS` | `source.ip`, `source.as_number`, `http.status_code` | `count >= 40` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `http_status` $\rightarrow$ `http.status_code` |
| **WEB-012** | High 403 Forbidden burst by Country | `WEB_ACCESS` | `source.geo_country_iso_code`, `source.as_number` | `count >= 100 and unique_ips >= 10` | 300s | `host.name\|source.geo_country_iso_code` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **WAF-001** | High ModSecurity WAF triggers (por IP) | `WAF` | `source.ip`, `waf.rule_id` | `count >= 15` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.waf.rule_id` $\rightarrow$ `waf.rule_id` |
| **WAF-002** | ModSecurity critical rule burst | `WAF` | `source.ip`, `waf.rule_id` | `count >= 5` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.waf.rule_id` $\rightarrow$ `waf.rule_id` |
| **WAF-003** | ModSecurity WAF attack from suspicious ASN | `WAF` | `source.ip`, `source.as_number` | `count >= 10` | 300s | `host.name\|source.as_number` | ✅ Migrada a ECS | `extra.asn.number` $\rightarrow$ `source.as_number` |
| **WAF-004** | ModSecurity WAF attack from risky country | `WAF` | `source.ip`, `source.geo_country_iso_code` | `count >= 12` | 300s | `host.name\|source.geo_country_iso_code` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **PANEL-001** | FileManager suspicious file upload | `PANEL` | `user.name`, `source.ip`, `file.directory` | `count >= 3` | 300s | `host.name\|user.name\|source.ip\|file.directory` | ✅ Migrada a ECS | `extra.file.dir` $\rightarrow$ `file.directory` |
| **PANEL-002** | WHM administrative login from new IP | `PANEL` | `user.name`, `source.ip` | `success_count >= 1` | 3600s | `host.name\|user.name` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **PANEL-003** | cPanel password change burst | `PANEL` | `user.name`, `source.ip` | `count >= 5` | 600s | `host.name\|user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **MAIL-001** | Mail auth failures (Dovecot) | `MAIL_AUTH` | `source.ip`, `service.name`, `event.outcome` | `fail_count >= 10` | 600s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.action` $\rightarrow$ `event.outcome` |
| **MAIL-001** | Mail auth failures (SMTP AUTH fail) | `MAIL_FLOW` | `source.ip`, `service.name`, `event.outcome` | `fail_count >= 10` | 600s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.action` $\rightarrow$ `event.outcome` |
| **MAIL-002** | Mail auth failures then success (Dovecot) | `MAIL_AUTH` | `user.name`, `source.ip`, `service.name` | `fail_count >= 8 and success_count >= 1` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **MAIL-002** | Mail auth failures then success (SMTP) | `MAIL_FLOW` | `user.name`, `source.ip`, `service.name` | `fail_count >= 6 and success_count >= 1` | 1800s | `host.name\|user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **MAIL-003** | High outbound mail volume (por domain) | `MAIL_FLOW` | `customer.domain_name`, `email.direction` | `count >= 300` | 600s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `domain` $\rightarrow$ `customer.domain_name` |
| **MAIL-003** | High outbound mail volume (por host) | `MAIL_FLOW` | `email.direction` | `count >= 800` | 600s | `host.name` | ✅ Migrada a ECS | `extra.direction` $\rightarrow$ `email.direction` |
| **MAIL-004** | Mail login from risky country | `MAIL_AUTH` | `source.ip`, `source.geo_country_iso_code` | `fail_count >= 3 or success_count >= 1` | 3600s | `host.name\|source.ip\|source.geo_country_iso_code` | ✅ Migrada a ECS | `geo_country` $\rightarrow$ `source.geo_country_iso_code` |
| **MAIL-005** | Outbound rate-limit exceeded (por domain) | `MAIL_FLOW` | `customer.domain_name`, `event.kind_detail` | `count >= 3` | 600s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `domain` $\rightarrow$ `customer.domain_name` |
| **MAIL-005** | Outbound rate-limit exceeded (por host) | `MAIL_FLOW` | `event.kind_detail` | `count >= 10` | 600s | `host.name` | ✅ Migrada a ECS | `extra.kind` $\rightarrow$ `event.kind_detail` |
| **MAIL-006** | Sustained rate-limit pressure | `MAIL_FLOW` | `customer.domain_name`, `event.kind_detail` | `count >= 15` | 1800s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `domain` $\rightarrow$ `customer.domain_name` |
| **MAIL-007** | Rate-limit exceeded with hourly indicator | `MAIL_FLOW` | `customer.domain_name`, `event.original_detail` | `count >= 3` | 600s | `host.name\|customer.domain_name` | ✅ Migrada a ECS | `domain` $\rightarrow$ `customer.domain_name` |
| **SYS-001** | SSH login from non-trusted country | `SSH_AUTH` | `event.outcome`, `service.name`, `source.geo_country_iso_code` | `count >= 1` | 3600s | `host.name\|user.name` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **SYS-002** | Privilege escalation detected (sudo/su) | `SYSTEM_LOGS` | `event.action`, `event.is_noise`, `message` | `count >= 3` | 300s | `host.name` | ✅ Migrada a ECS | `extra.event_type` $\rightarrow$ `event.action` |
| **SYS-003** | Suspicious cron modification | `SYSTEM_LOGS` | `event.action`, `event.is_noise`, `message` | `count >= 5` | 300s | `host.name` | ✅ Migrada a ECS | `extra.event_type` $\rightarrow$ `event.action` |
| **RES-001** | Sustained high CPU / load (sar -q) | `SYSTEM_METRICS` | `event.action`, `metric.family`, `metric.name` | `count >= 5 and ld1 >= 6` | 300s | `host.name` | ✅ Migrada a ECS | `extra.metric.family` $\rightarrow$ `metric.family` |
| **RES-002** | Excessive PHP processes / saturation | `SYSTEM_METRICS` | `event.action`, `metric.family`, `metric.name` | `count >= 5 and ld1pc >= 2.0` | 300s | `host.name` | ✅ Migrada a ECS | `extra.metric.family` $\rightarrow$ `metric.family` |
| **RES-003** | Sustained high RAM usage (sar -r) | `SYSTEM_METRICS` | `event.action`, `metric.family`, `metric.name` | `count >= 5 and mem_pct >= 92` | 300s | `host.name` | ✅ Migrada a ECS | `extra.metric.family` $\rightarrow$ `metric.family` |
| **MULTI-001** | Same IP attacking multiple hosts | `WEB_ACCESS` | `source.ip`, `source.as_number` | `count >= 200 and unique_servers >= 2` | 1800s | `source.ip` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **MULTI-002** | Auth fail then success in another host | `SSH_AUTH` | `user.name` | `fail_count >= 3 and unique_servers >= 2` | 1800s | `user.name` | ✅ Migrada a ECS | `username` $\rightarrow$ `user.name` |
| **MULTI-003** | Same ASN flooding multiple servers | `WEB_ACCESS` | `source.ip`, `source.as_number` | `count >= 1500 and unique_servers >= 3` | 1800s | `source.as_number` | ✅ Migrada a ECS | `extra.asn.number` $\rightarrow$ `source.as_number` |
| **LFD-001** | Burst de bloqueos LFD (por IP) | `SECURITY_AGENT` | `source.ip`, `event.kind_detail`, `event.outcome` | `count >= 12` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `ip_client` $\rightarrow$ `source.ip` |
| **LFD-002** | Bloqueos LFD desde subnet /24 | `SECURITY_AGENT` | `source.ip`, `ip_subnet24` | `count >= 40 and unique_ips >= 10` | 600s | `host.name\|ip_subnet24` | ✅ Migrada a ECS | `ip_subnet24` calculado dinámicamente |
| **LFD-003** | Bloqueos LFD por ASN | `SECURITY_AGENT` | `source.ip`, `source.as_number` | `count >= 120 and unique_ips >= 25` | 600s | `host.name\|source.as_number` | ✅ Migrada a ECS | `extra.asn.number` $\rightarrow$ `source.as_number` |
| **LFD-004** | Bloqueos LFD por país | `SECURITY_AGENT` | `source.ip`, `source.geo_country_iso_code` | `count >= 160 and unique_ips >= 35` | 600s | `host.name\|source.geo_country_iso_code` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **LFD-005** | Campaña LFD cross-server por ASN | `SECURITY_AGENT` | `source.ip`, `source.as_number` | `count >= 250 and unique_servers >= 3` | 1800s | `source.as_number` | ✅ Migrada a ECS | `extra.asn.number` $\rightarrow$ `source.as_number` |
| **LFD-006** | Campaña LFD cross-server por país | `SECURITY_AGENT` | `source.ip`, `source.geo_country_iso_code` | `count >= 350 and unique_servers >= 3` | 1800s | `source.geo_country_iso_code` | ✅ Migrada a ECS | `extra.geo.country_code` $\rightarrow$ `source.geo_country_iso_code` |
| **LFD-007** | Bloqueos LFD por razón específica | `SECURITY_AGENT` | `source.ip`, `event.reason` | `count >= 6` | 300s | `host.name\|source.ip` | ✅ Migrada a ECS | `extra.reason` $\rightarrow$ `event.reason` |

---

## 🔬 Resumen de Ejecución y Cobertura de Pruebas

- **Total de Reglas Auditadas**: **57**
- **Reglas Migradas a Estándar ECS v1.0.0**: **57** (100%)
- **Reglas Deprecadas**: **0**
- **Total de Pruebas Unitarias Ejecutadas**: **112**
- **Pruebas Exitosas (Passed)**: **112 (100%)**
- **Pruebas Fallidas (Failed)**: **0 (0%)**
- **Pruebas de Equivalencia (Realtime NATS vs Reprocess OpenSearch)**: ✅ **Verificadas e Idénticas**
