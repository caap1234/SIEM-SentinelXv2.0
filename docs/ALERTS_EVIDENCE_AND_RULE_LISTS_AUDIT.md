# Auditoría y Plan de Corrección Integral: Alertas, Evidencia y Listas de Seguridad

> **Estado:** Propuesta de Diseño e Implementación  
> **Fecha:** 2026-08-18  
> **Versión:** 1.0  

---

## 1. Estado Actual de la Arquitectura

### 1.1 Flujo Alert -> Event -> Evidence
La relación física y lógica actual en la base de datos PostgreSQL se define de la siguiente manera:
- **`alerts`** ([alert.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/models/alert.py)):
  - `opensearch_event_id` (String): ID de correlación único del evento principal (o el primero de la ventana).
  - `s3_key` (String): Clave del objeto inmutable en MinIO S3 que almacena el raw empaquetado del evento.
  - `evidence` (JSONB): Contiene:
    - `"event_ids"`: Lista de IDs de eventos que dispararon la regla en la ventana temporal.
    - `"group_by"`: Lista de campos agrupadores.
    - `"group_values"`: Valores correspondientes de agrupación.
    - `"raw_samples"`: Lista de textos del log (vacía en las capturas de la base de datos).

### 1.2 ¿Por qué no se muestra el Raw Log en la vista principal?
En [rule_engine_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/services/rule_engine_v2.py#L632-L643), la sección de evidencia intenta cargar los raw logs de la base de datos relacional PostgreSQL consultando la tabla `rawlogs` si `include_raw` es `True`. Sin embargo, esto falla o retorna vacío (`raw_samples: []`) por los siguientes factores:
1. **Inconsistencia de Referencia:** Los `event_ids` almacenados corresponden a los UUIDs de la tabla `events`. Sin embargo, `raw_id` en `events` apunta al id secuencial en `rawlogs`. Si no se configuró correctamente la persistencia del raw o el log fue purgado por políticas de retención de PostgreSQL, la consulta devuelve vacío.
2. **Duplicación por Diseño:** Para cumplir el principio de **no duplicar logs completos en PostgreSQL**, la tabla `rawlogs` tiene tiempos de retención sumamente cortos o directamente no se inyectan logs en crudo, prefiriendo la inmutabilidad en MinIO (S3) y la indexación en OpenSearch.
3. **Falta de resolución en caliente:** La UI del modal de Alertas ([alertas.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/alertas.astro)) carga la metadata local de PostgreSQL y no intenta resolver los raw logs desde OpenSearch o MinIO si `raw_samples` está vacío.

### 1.3 Funcionamiento del Botón MinIO (S3)
El botón "Ver Log Original en MinIO (S3)" llama al endpoint `/alerts/{alert_id}/evidence`. Al auditar [alerts.py:get_alert_evidence](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/alerts.py#L541-L580):
- Si falla la conexión a MinIO o no se encuentra el objeto con la `s3_key` correspondiente, el endpoint tiene un fallback cableado que devuelve contenido sintético generado en caliente:
  ```python
  "raw_evidence": raw_content or f"[SentinelX S3 Forensics] Raw log sample for Alert #{alert_id}\nRule: {alert.rule_name}\nServer: {alert.server}\nStatus: {alert.status}"
  ```
- Esto genera confusión, ya que se presenta como "Log Original" contenido que es puramente sintético.

---

## 2. Clasificación y División de Listas de Seguridad

Las listas de seguridad no deben tratarse de forma homogénea ni aplicarse ciegamente a todas las reglas. Se dividen en tres grandes categorías según su naturaleza y el impacto esperado en el motor de detección:

```
                  ┌──────────────────────────────────────────────┐
                  │          Listas de Seguridad (SIEM)          │
                  └──────────────────────┬───────────────────────┘
                                         │
         ┌───────────────────────────────┼──────────────────────────────┐
         ▼                               ▼                              ▼
┌─────────────────┐             ┌──────────────────┐           ┌──────────────────┐
│ 1. Whitelists   │             │ 2. Blacklists    │           │ 3. Detección     │
│ (Listas de      │             │ (Listas de       │           │ (Listas de       │
│ Confianza)      │             │ Bloqueo)         │           │ Referencia)      │
├─────────────────┤             ├──────────────────┤           ├──────────────────┤
│ - whitelist_ip  │             │ - blm_ignore     │           │ - suspicious_asn │
│ - whitelist_cidr│             │ - blm_shared     │           │ - suspicious_tok │
│ - trusted_count │             │ - blm_pmg        │           │ - privileged_user│
│ - trusted_asn   │             │                  │           │ - path_keywords  │
│ - trusted_server│             │                  │           │ - phishing_tokens│
└─────────────────┘             └──────────────────┘           └──────────────────┘
```

### 2.1 Whitelists (Listas de Confianza / Exclusiones)
* **Propósito:** Excluir eventos legítimos de la generación de alertas (evitar falsos positivos).
* **Tipos de Listas:**
  - `whitelist_ip` / `whitelist_cidr`: IPs/Redes exentas globalmente o por tenant.
  - `trusted_country`: Países cuyas conexiones exitosas nunca deben alertar.
  - `trusted_asn`: Autotransportes de red (ISPs, CDNs de confianza) exentos.
  - `trusted_server`: Servidores internos conocidos que generan ruido legítimo.
  - `exception_rule`: Excepciones hiper-específicas de grano fino (`rule_code` + `value_type`).
* **Comportamiento:** Si un evento coincide con una Whitelist habilitada para esa regla, la regla se **descarta de inmediato** y se genera un registro en la tabla de trazabilidad (`security_list_ignore_log`).

### 2.2 Blacklists (Listas de Bloqueo / RBL / Reputación)
* **Propósito:** Identificar direcciones IP y activos maliciosos que requieren monitoreo estricto o alerta inmediata.
* **Tipos de Listas:**
  - `blm_ignore`: IPs a ignorar dentro del sync del BlacklistMaster para evitar falsos positivos de red.
  - `blm_shared`: IPs catalogadas como Hosting Compartido (afectan la severidad o causan segregación).
  - `blm_pmg`: IPs de Proxmox Mail Gateway (Mail relays).
* **Comportamiento:** Se utilizan para enriquecer alertas o gatillar detecciones directas (como `BLM-001`).

### 2.3 Listas de Detección (Listas de Referencia)
* **Propósito:** Servir como variables dinámicas que las reglas evalúan mediante operadores de comparación (substrings, tokens, coincidencia exacta).
* **Tipos de Listas:**
  - `suspicious_asn_org_tokens` / `suspicious_asn_numbers`: Organizaciones o números de red bajo sospecha.
  - `web_exploit_path_tokens` / `sensitive_path_keywords`: Keywords y rutas sospechosas en URLs (ataques LFI, inyecciones, escaneos).
  - `phishing_host_tokens` / `phishing_path_keywords`: Hosts y strings típicos de phishing.
  - `privileged_users`: Nombres de cuentas críticas que no deben autenticarse de forma anómala.
* **Comportamiento:** **No se aplican globalmente**. Solo son consultadas si la regla de detección referencia explícitamente a la lista en su configuración `match` (ej. `"user.name": {"in_ref": "privileged_users"}`).

---

## 3. Propuesta de Arquitectura y Precedencia de Evaluación

Para evitar lógicas implícitas o confusas donde todas las reglas evalúan todas las listas, se propone una **Evaluación Condicional y Explícita**.

### 3.1 Precedencia Formal del Engine

El motor evaluará un evento siguiendo estrictamente este orden:

```
                     [ Evento Entrante ]
                              │
                              ▼
            1. Excepciones Específicas de Regla
                 (¿Coincide con IP/Usuario/ASN?)
                    /                      \
                 (Sí)                      (No)
                  /                          \
                 ▼                            ▼
         [ IGNORAR EVENTO ]          2. Whitelists Aplicables
         (Ignore log rule)            (Tenant o Globales si aplica)
                                         /              \
                                      (Sí)              (No)
                                       /                  \
                                      ▼                    ▼
                              [ IGNORAR EVENTO ]     3. Condiciones de la Regla
                              (Ignore log global)      (Match de campos +
                                                       Listas de Detección)
                                                          /           \
                                                      (Match)      (No Match)
                                                        /               \
                                                       ▼                 ▼
                                               [ GENERAR ALERTA ]    [ DESCARTAR ]
```

1. **Excepción Específica de Regla:** Se consulta la lista `exception_rule` filtrando por el código de la regla (`rule_code`). Si coincide el IP, usuario, país o ASN, se descarta.
2. **Whitelists del Tenant / Globales:** Si la regla tiene habilitada la política de whitelist (`whitelist_policy` != `'ignore'`), se evalúan las listas `whitelist_ip`, `whitelist_cidr`, `trusted_country` y `trusted_asn`. Si coincide, se descarta.
3. **Condición de Regla + Listas de Detección:** Se evalúan los filtros directos y las referencias a las Listas de Detección de forma explícita.

### 3.2 Trazabilidad de Descarte (Trazar por qué NO disparó)
Cuando el engine descarta un evento por exclusión, se persistirá de forma asíncrona en la tabla `security_list_ignore_log` guardando la tupla:
- `rule_code`
- `ignore_reason` (ej. `rule_exception`, `trusted_country`, `trusted_ip`)
- `value_matched` (ej. `rule:WEB-004|ip:1.2.3.4`)
- `event_id` / `ip_client` / `server`

---

## 4. Plan de Implementación por Fases

### Fase 1: Corrección de Visualización de Alertas y Evidencia
1. **Backend - Endpoint de Búsqueda:**
   - Habilitar en `app/routers/alerts.py` el filtrado por `q` para que busque por coincidencia de subcadena en `rule_name`, `rule_id`, además del `group_key` y la entidad actual.
2. **Frontend - Input de Búsqueda:**
   - Eliminar el atributo `disabled` del input `data-filter-q` en `front/src/pages/dashboard/alertas.astro`.
   - Modificar la llamada a la API para enviar el parámetro `q` correctamente al backend.
3. **UI de Alerta - Contexto y Raw Logs:**
   - Si `raw_samples` en la alerta está vacío, agregar una consulta en caliente al backend `/alerts/{alert_id}/raw` para extraer el `log.original` desde OpenSearch usando `opensearch_event_id`, o desde MinIO usando `s3_key`.
   - Modificar el endpoint `/alerts/{alert_id}/evidence` para que si el log es sintético (fallback por error en S3), retorne un campo indicando `is_synthetic: true`.
   - Modificar el modal de la UI para advertir claramente mediante un badge o etiqueta informativa `[Contenido Sintético / No Forense]` si no se pudo validar la integridad en S3.

### Fase 2: Configuración Explícita Rule <-> Security Lists (Bindings)
1. **Modelo de Base de Datos:**
   - Crear una tabla asociativa `rule_list_bindings`:
     - `rule_id` (FK rules_v2.id)
     - `list_type` / `list_name` (String)
     - `purpose` (String: `'detection'` | `'whitelist'` | `'blacklist'`)
     - `enabled` (Boolean)
     - `match_field` (String, ej: `'url.path'`)
     - `operator` (String, ej: `'contains_any_ref'`)
2. **Backend - Refactorizar RuleEngineV2:**
   - Cambiar la lógica implícita actual de `_is_trusted_event_for_rule` para que respete los bindings de la base de datos y la directiva configurada en la regla.
3. **UI de Edición de Reglas:**
   - Implementar la sección "Listas y Excepciones" en el formulario de creación/edición de reglas.

### Fase 3: Cache e Invalidación Reactiva
1. **Invalidación de Caché:**
   - Implementar en `SecurityListService` un listener de NATS. Al crear/editar/eliminar una lista o excepción en `/api/v1/lists`, se publica un mensaje `lists.invalidated`.
   - Todos los workers del SOC escuchan el evento y limpian su caché en memoria (`_last_load = None`) para forzar la recarga síncrona.
