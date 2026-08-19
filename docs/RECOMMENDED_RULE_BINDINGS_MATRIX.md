# SentinelX SIEM — Matriz de Reglas V2 y Bindings Recomendados

Este documento especifica la **Matriz Completa de Reglas V2 (57 Reglas)**, describiendo el propósito de cada regla, qué patrones analiza en los logs y las **listas de seguridad (Bindings) recomendadas** para asociar a cada una de ellas de forma explícita.

---

## Principios de la Arquitectura de Bindings V2

1. **Relaciones 100% Explícitas:** Ninguna regla V2 aplica whitelists o listas de confianza implícitas o mágicas. Toda relación `Rule <-> List` debe configurarse mediante un `RuleListBinding`.
2. **Exclusión General (`whitelist_ip` y `trusted_server`):** Salvo en las reglas de RBL (`BLM-001`), todas las reglas deben contar con bindings de **Exclusión** para `whitelist_ip` y `trusted_server` (`source.ip`, `in_ref` o `cidr_match`).
3. **Roles de Bindings:**
   - `exclusion`: Si el evento coincide con la lista, se descarta **antes** de entrar a la ventana temporal o contadores. (Lógica `OR`).
   - `detection`: La coincidencia con la lista es un requisito para que la regla evalúe el match base. (Lógica combinada por `detection_bindings_operator`: `AND` / `OR`).
   - `context`: Se evalúa **después** de alcanzar el threshold para enriquecer evidencia, etiquetas o severidad (`action_config`).

---

## Catálogo de las 15 Listas de Seguridad Disponibles

| Nombre de Lista (`list_name`) | Tipo (`list_type`) | Propósito | Campo ECS habitual |
| :--- | :--- | :--- | :--- |
| **`whitelist_ip`** | `whitelist_ip` | IPs de confianza absoluta (para no generar falsos positivos). | `source.ip` |
| **`trusted_server`** | `trusted_server` | IPs de servidores internos de la infraestructura Neubox. | `source.ip` |
| **`trusted_country`** | `trusted_country` | Países autorizados / de confianza (ej. `MX`). | `geo.country_iso_code` |
| **`trusted_asn`** | `trusted_asn` | Sistemas Autónomos (ASNs) de confianza (ej. Microsoft, Google). | `source.as_number` |
| **`blm_shared`** | `blm_shared` | IPs de Shared Hosting monitoreadas por BlacklistMaster. | `source.ip` |
| **`blm_pmg`** | `blm_pmg` | Relays de correo Proxmox Mail Gateway (pmg1..pmg15). | `source.ip` |
| **`blm_ignore`** | `blm_ignore` | IPs ignoradas explícitamente del monitoreo RBL. | `source.ip` |
| **`phishing_host_tokens`** | `list_ref` | Tokens en vhosts/dominios de phishing (ej. `banamex`, `bbva`). | `url.domain` |
| **`phishing_path_keywords`** | `list_ref` | Palabras clave en rutas de phishing (ej. `verify`, `login`). | `url.path` |
| **`suspicious_file_exts`** | `list_ref` | Extensiones de webshells o binarios (`.phtml`, `.phar`, `.jsp`). | `file.extension` |
| **`sensitive_path_keywords`** | `list_ref` | Archivos/rutas sensibles (`/.env`, `/.git`, `wp-config.php`). | `url.path` |
| **`web_exploit_path_tokens`** | `list_ref` | Patrones de exploits/SQLi/RCE (`/etc/passwd`, `union select`). | `url.path` |
| **`privileged_users`** | `list_ref` | Cuentas privilegiadas del sistema (`root`, `admin`, `sysadmin`). | `user.name` |
| **`suspicious_asn`** | `suspicious_asn` | ASNs sospechosos / Datacenters de riesgo. | `source.as_number` |
| **`suspicious_asn_org_tokens`**| `list_ref` | Organizaciones ASN de hosting o proxy (`DIGITALOCEAN`, `OVH`).| `source.as_org` |

---

## Matriz Completa de Reglas V2 y Bindings Recomendados

### 1. Familia WEB — Tráfico HTTP, Scans y Exploits

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`WEB-001`** | **Path scanning** (Escaneo de rutas comunes por bots). | `whitelist_ip`<br>`trusted_server`<br>`sensitive_path_keywords` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`url.path` | `in_ref`<br>`in_ref`<br>`contains_any_ref` |
| **`WEB-002`** | **XML-RPC abuso** (Fuerza bruta o amplificación en WordPress). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-003`** | **Patrones de exploits web** (Intentos de RCE, SQLi, LFI, Command Injection). | `whitelist_ip`<br>`trusted_server`<br>`web_exploit_path_tokens` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`url.path` | `in_ref`<br>`in_ref`<br>`contains_any_ref` |
| **`WEB-004`** | **Acceso a archivos sensibles** (Acceso a `.env`, `.git`, `wp-config.php`, backups `.zip`/`.sql`). | `whitelist_ip`<br>`trusted_server`<br>`sensitive_path_keywords` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`url.path` | `in_ref`<br>`in_ref`<br>`contains_any_ref` |
| **`WEB-005`** | **WP login abuse** (Fuerza bruta masiva a `/wp-login.php`). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-006`** | **HTTP Flood single IP** (Ataque DoS/DDoS de alto volumen desde una sola IP). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-007`** | **Phishing / Scam keyword** (Alojamiento de páginas de phishing en vhosts). | `whitelist_ip`<br>`trusted_server`<br>`phishing_host_tokens`<br>`phishing_path_keywords` | Exclusion<br>Exclusion<br>**Detection**<br>**Detection** *(Operador OR)* | `source.ip`<br>`source.ip`<br>`url.domain`<br>`url.path` | `in_ref`<br>`in_ref`<br>`contains_any_ref`<br>`contains_any_ref` |
| **`WEB-008`** | **HTTP flood por Subred /24** (DDoS distribuido desde subred `/24`). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-009`** | **HTTP flood por País** (Inundación de peticiones desde países no habituales). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`WEB-010`** | **ModSecurity Flood** (Alto volumen de bloqueos WAF gatillados por una misma IP). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-011`** | **Errores 5xx masivos** (Saturación o fallos en sitios web cliente). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`WEB-012`** | **HTTP flood desde ASN sospechoso** (Peticiones masivas provenientes de Datacenters/Proxiers). | `whitelist_ip`<br>`trusted_server`<br>`suspicious_asn`<br>`suspicious_asn_org_tokens` | Exclusion<br>Exclusion<br>**Detection**<br>**Detection** | `source.ip`<br>`source.ip`<br>`source.as_number`<br>`source.as_org` | `in_ref`<br>`in_ref`<br>`in_ref`<br>`contains_any_ref` |

---

### 2. Familia AUTH — Autenticación y Accesos (SSH, Dovecot, cPanel)

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AUTH-001`** | **SSH Brute Force** (Muchos fallos de contraseña SSH desde una IP). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`AUTH-002`** | **Credential Stuffing (SSH / Dovecot)** (Una IP probando múltiples usuarios distintos). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`AUTH-003`** | **Password Guessing exitoso** (Fallos consecutivos seguidos de login exitoso). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`AUTH-004`** | **Ataque distribuido a un usuario** (Múltiples IPs atacando la misma cuenta). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`AUTH-005`** | **Login desde país no confiable** (Autenticación exitosa desde países no autorizados). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`AUTH-006`** | **Login Privilegiado desde nueva IP** (Accesos `root`/`admin`/`sysadmin` desde IPs desconocidas). | `whitelist_ip`<br>`trusted_server`<br>`privileged_users` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`user.name` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`AUTH-007`** | **Abuso de Autenticación cPanel** (Intentos fallidos masivos en puerto 2083/cPanel). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |

---

### 3. Familia FILE — Carga de Webshells e Integridad de Archivos

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`FILE-001`** | **PHP File Uploaded en rutas de riesgo** (Subida de scripts PHP en `/tmp`, `/uploads`, `/images`). | `whitelist_ip`<br>`trusted_server`<br>`suspicious_file_exts` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`file.extension` | `in_ref`<br>`in_ref`<br>`contains_any_ref` |
| **`FILE-002`** | **Violación de Integridad en WordPress Core** (Inyección de código en `index.php`, `wp-settings.php`). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`FILE-003`** | **Ofuscación de archivos / FileManager Burst** (Uso de `eval(base64_decode)` o ráfagas en FileManager). | `whitelist_ip`<br>`trusted_server`<br>`suspicious_file_exts` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`file.extension` | `in_ref`<br>`in_ref`<br>`contains_any_ref` |
| **`FILE-004`** | **Ejecutable en `/tmp` o `/dev/shm`** (Creación o ejecución de binarios sospechosos). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |

---

### 4. Familia MAIL — Flujo y Autenticación de Correo (Exim / Dovecot)

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`MAIL-001`** | **Fallos de autenticación SMTP / IMAP** (Fuerza bruta a cuentas de correo). | `whitelist_ip`<br>`trusted_server`<br>`blm_pmg` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`source.ip` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`MAIL-002`** | **Mail login exitoso tras fallos** (Posible compromiso de cuenta de correo). | `whitelist_ip`<br>`trusted_server`<br>`blm_pmg` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`source.ip` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`MAIL-003`** | **Alto volumen de envío saliente** (Cuentas o dominios emitiendo Spam masivo). | `whitelist_ip`<br>`trusted_server`<br>`blm_pmg` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`source.ip` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`MAIL-004`** | **Mail login desde país de riesgo** (Acceso a buzón de correo desde países no confiables). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`MAIL-005` / `006` / `007`** | **Límite de tasa de salida excedido (Rate-limit)** (Exim rate-limit reached por hora/dominio). | `whitelist_ip`<br>`trusted_server`<br>`blm_pmg` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`source.ip` | `in_ref`<br>`in_ref`<br>`in_ref` |

---

### 5. Familia SYS, RES y MULTI — Sistema, Recursos y Ataques Distribuidos

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SYS-001`** | **SSH login no confiable por país** (Acceso por consola desde ubicaciones no autorizadas). | `whitelist_ip`<br>`trusted_server`<br>`trusted_country` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`geo.country_iso_code` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`SYS-002`** | **Escalada de Privilegios** (Uso anómalo de `sudo`, `su`, `pkexec`, `polkit`). | `whitelist_ip`<br>`trusted_server`<br>`privileged_users` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`user.name` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`SYS-003`** | **Modificación sospechosa de Cron** (Persistencia maliciosa en `/etc/cron*`). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`RES-001` / `002` / `003`** | **Saturación de CPU / RAM / Procesos** (Métricas `sar` o escasez de recursos en servidor). | `trusted_server` | Exclusion | `source.ip` | `in_ref` |
| **`MULTI-001`** | **Misma IP atacando múltiples servidores** (Ataque coordinado cross-server). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`MULTI-002`** | **Credential Reuse en varios hosts** (Fuerza bruta transversal a la infraestructura). | `whitelist_ip`<br>`trusted_server` | Exclusion<br>Exclusion | `source.ip`<br>`source.ip` | `in_ref`<br>`in_ref` |
| **`MULTI-003`** | **Mismo ASN inundando varios servidores** (Ataque botnet/ASN distribuido). | `whitelist_ip`<br>`trusted_server`<br>`suspicious_asn` | Exclusion<br>Exclusion<br>**Detection** | `source.ip`<br>`source.ip`<br>`source.as_number` | `in_ref`<br>`in_ref`<br>`in_ref` |

---

### 6. Familia LFD y BLM — Agente de Bloqueos y Monitoreo de Blacklists

| Regla | ¿De qué es y qué busca? | Binding Recomendado | Rol | Campo ECS | Operador |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`LFD-001` a `008`** | **Bloqueos de LFD / CSF Firewall** (Ráfagas de bloqueos automáticos por IP, Subred o ASN). | `whitelist_ip`<br>`trusted_server`<br>`blm_ignore` | Exclusion<br>Exclusion<br>**Exclusion** | `source.ip`<br>`source.ip`<br>`source.ip` | `in_ref`<br>`in_ref`<br>`in_ref` |
| **`BLM-001`** | **Monitoreo de Blacklists RBL** (Revisar si IPs de Shared o PMG están en RBLs públicas). | **`blm_ignore`**<br>*(NO usar whitelist_ip ni trusted_server aquí)* | **Exclusion** | `source.ip` | `in_ref` |
