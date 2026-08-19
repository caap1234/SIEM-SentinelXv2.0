# Matriz de Relación: Reglas vs Listas de Seguridad y Confianza (SIEM)

Esta matriz detalla las reglas del sistema, qué listas deben consumir de manera explícita, qué campos del evento normalizado ECS deben evaluarse y qué políticas de Whitelist/Blacklist aplican.

| Rule ID | Rule Name | Dataset / Source | Lista a Evaluar | Tipo de Lista | Campo ECS Evaluado | Operador | Whitelist Aplica | Blacklist Aplica | Excepciones de Regla | Estado Actual | Cambio Recomendado |
|---------|-----------|------------------|-----------------|---------------|--------------------|----------|------------------|------------------|----------------------|---------------|-------------------|
| **AUTH-006** | Privileged login from new IP | `SSH_AUTH`, `PANEL` | `privileged_users` | Detección (Referencia) | `user.name` | `in_ref` | Sí | No | IPs de Admins | Implícito / Parcial | Pasar a binding explícito en DB. Configurar excepciones por IP |
| **WEB-004** | Access to sensitive files | `WEB_ACCESS` | `sensitive_path_keywords` | Detección (Referencia) | `url.path` | `contains_any_ref` | Sí | No | IPs de scanners internos | Implícito | Mapear contra `url.path` (ECS canonizado) en lugar de `extra.http.path` |
| **WEB-005** | Web exploit patterns | `WEB_ACCESS`, `WAF` | `web_exploit_path_tokens` | Detección (Referencia) | `url.path` | `contains_any_ref` | Sí | No | IPs autorizadas | Incompleto | Integrar validación directa mediante bindings en base de datos |
| **WEB-010** | Phishing host detected | `WEB_ACCESS` | `phishing_host_tokens` | Detección (Referencia) | `url.domain` / `url.original` | `contains_any_ref` | Sí | No | Ninguna | Inactivo | Activar y ligar la lista al motor de reglas de forma explícita |
| **NET-002** | Traffic from suspicious ASN | `SYSTEM_LOGS` | `suspicious_asn_numbers` | Detección (Referencia) | `source.as_number` | `in_ref` | No | Sí | Ninguna | Parcial | Cambiar referencia legacy `extra.asn.number` a `source.as_number` |
| **BLM-001** | IP listed in RBL | `BLACKLISTMASTER` | `blm_ignore` | Blacklist (Bloqueo) | `source.ip` | `not_in_ref` | No | Sí | IPs del Sync | Parcial | Filtrar IPs listadas en `blm_ignore` usando subredes CIDR reales en PostgreSQL |

---

## Leyenda de Tipos de Lista y Operadores

- **`in_ref`**: El valor del campo en el evento debe ser un miembro exacto de la lista especificada.
- **`contains_any_ref`**: El valor del campo en el evento debe contener al menos uno de los tokens o subcadenas presentes en la lista.
- **`not_in_ref`**: Exclusión explícita. El evento es descartado si el valor se encuentra en la lista.
- **Whitelist Aplica (Sí/No)**: Define si la regla de detección respeta las exclusiones globales de la plataforma (`whitelist_ip`, `whitelist_cidr`, `trusted_country`, `trusted_asn`).
- **Excepciones de Regla**: Entradas en la lista `exception_rule` que coinciden con el `rule_code` actual.
