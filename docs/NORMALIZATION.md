# Guía de Normalización de Parsers - SentinelX SIEM

## 1. Principio de Normalización Canónica

Todos los parsers de SentinelX SIEM deben transformar las líneas de logs crudas en una instancia del objeto `NormalizedEvent` (`app/schemas/normalized_event.py`).

No se permite el uso de nombres arbitrarios como `client_ip`, `src`, `remote_host` o `user_name` en los campos primarios de eventos.

---

## 2. Tabla de Mapeo de Normalización

| Concepto | Campo Antiguo / Heterogéneo | Campo Canónico Estándar |
| :--- | :--- | :--- |
| **IP del Cliente de Origen** | `ip_client`, `src_ip`, `remote_addr`, `rip` | `source.ip` |
| **Puerto del Cliente** | `port`, `src_port` | `source.port` |
| **IP del Servidor Destino** | `ip_server`, `dst_ip`, `lip` | `destination.ip` |
| **Usuario Autenticado** | `username`, `user`, `auth_user` | `user.name` / `email.authenticated_user` |
| **Dominio** | `domain`, `vhost`, `host` | `url.domain` / `customer.domain_name` |
| **Método HTTP** | `extra.http.method`, `method` | `http.method` |
| **Código Estado HTTP** | `extra.http.status`, `status` | `http.status_code` |
| **Ruta Solicitada** | `extra.http.path`, `uri` | `url.path` |
| **ID de Cola Exim** | `message_id`, `exim_id` | `email.queue_id` |
| **Remitente Correo** | `from_addr`, `sender` | `email.from_address` |
| **Destinatario Correo** | `to_addr`, `rcpt` | `email.to_address` |
| **Proceso Executable** | `proc_path` | `process.executable` |
| **Hash SHA-256** | `sha256`, `hash` | `file.hash_sha256` |

---

## 3. Manejo de Eventos Desconocidos o Malformados

Cuando una línea no coincide con las expresiones regulares conocidas del parser:
1. El parser **NO debe lanzar una excepción** no capturada.
2. Si la línea es irrelevante (e.g. líneas en blanco, comentarios), retorna `None`.
3. Si la línea es una falla o formato irreconocible, el pipeline la envía al dataset `sentinelx.dlq` / `parsing_errors` conservando el texto en `log.original` y registrando el motivo en los metadatos.
