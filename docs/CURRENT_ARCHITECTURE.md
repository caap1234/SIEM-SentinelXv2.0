# Documento de Arquitectura Actual - SentinelX SIEM (v0.2.0)

## 1. Resumen de la Auditoría Técnica

Este documento presenta los hallazgos de la auditoría técnica exhaustiva realizada sobre el repositorio **SentinelX-SIEM** (versión 0.2.0).

El estado actual del proyecto corresponde a un **prototipo monolítico desacoplado únicamente mediante tareas asíncronas apoyadas en PostgreSQL**. Aunque presenta intenciones de separación entre ingestión, parseo y motor de correlación, la implementación carece de las garantías requeridas para una plataforma SIEM empresarial enfocada en entornos de hosting masivos (cPanel, DirectAdmin, Exim, Apache/Nginx, ModSecurity, Imunify360, CSF/LFD).

---

## 2. Diagrama de la Arquitectura Actual

```mermaid
flowchart TD
    subgraph Fuentes ["Servidores Linux (cPanel / DirectAdmin)"]
        Agent["sentinelx-agent.sh (Bash)"]
    end

    subgraph Backend ["FastAPI Ingest & Web Server"]
        LogsAPI["POST /logs/upload /ingest"]
        LocalDisk["UPLOADED_LOGS_DIR (/app/uploaded_logs)"]
    end

    subgraph Storage ["Almacén Único: PostgreSQL"]
        LogUploadsTable["log_uploads (Estado: queued, parsing, parsed, error)"]
        RawLogsTable["raw_logs (Líneas de log crudas)"]
        EventsTable["events (Eventos normalizados - State: pending)"]
        AlertsTable["alerts & incidents"]
    end

    subgraph Workers ["Workers Asíncronos (Polling SQL)"]
        ParsingWorker["parsing_worker_loop.py\n(FOR UPDATE SKIP LOCKED)"]
        EngineWorker["engine_worker_loop.py\n(FOR UPDATE SKIP LOCKED)"]
    end

    subgraph Frontend ["Astro / React UI"]
        UI["Dashboard & Management"]
    end

    Agent -->|HTTP Multipart File Upload\n(Sin mTLS, API Key en cabecera)| LogsAPI
    LogsAPI -->|Escribe archivo temporal| LocalDisk
    LogsAPI -->|Inserta registro| LogUploadsTable

    ParsingWorker -->|Polling 'queued'| LogUploadsTable
    ParsingWorker -->|Lee archivo de disco| LocalDisk
    ParsingWorker -->|Inserta raw_logs| RawLogsTable
    ParsingWorker -->|Inserta events| EventsTable

    EngineWorker -->|Polling 'pending'| EventsTable
    EngineWorker -->|Ejecuta RuleEngineV2| EngineWorker
    EngineWorker -->|Crea alertas e incidentes| AlertsTable

    UI <-->|HTTP REST JWT| LogsAPI
```

---

## 3. Matriz de Auditoría de Componentes

| Componente | Estado Actual | Riesgos Principales | Limitaciones Clave | Acción Propuesta |
| :--- | :--- | :--- | :--- | :--- |
| **SentinelX Agent** | Script Bash (`sentinelx-agent.sh`) de 704 líneas. | **PÉRDIDA MASIVA DE EVENTOS**: Si la API está caída o responde 5xx/429, ejecuta `reset_for_next_run_due_to_failure` que **purga el spool y borra los `.state` (offsets)**. | No es un binario compilado confiable. Depende de utilidades de sistema (`curl`, `dd`, `gzip`, `python3`, `sar`). Sin mTLS. | Rediseñar en agente robusto con spool persistente **inmutable ante caídas del backend**, reintentos exponenciales con jitter y mTLS. |
| **API de Ingesta** | FastAPI Router (`app/routers/logs.py`). | **Bloqueante / E/S Disco**: Recibe archivos completos (hasta 1GB), los guarda en disco local y los registra en DB. Sin sanitización profunda de compresión (gzip bomb). | Procesa archivos batch completos por HTTP multipart en lugar de streaming/event-driven. Sin deduplicación ni idempotencia real. | Transformar en API Stateless que valide agentes, limite rate/payloads y envíe eventos comprimidos directamente al Bus de Eventos. |
| **Bus de Eventos** | **INEXISTENTE**. | No hay buffer intermedio. Todo evento debe transitar por PostgreSQL. | Cuello de botella severo. Locks de base de datos (`FOR UPDATE SKIP LOCKED`) consumen I/O de PostgreSQL. | Introducir **NATS JetStream** / **Redpanda** como Event Broker persistente con DLQ y ACK explicito. |
| **Base de Datos** | **PostgreSQL 16**. | **SOBRECARGA MULTIPROPÓSITO**: Usado como cola de tareas, almacén masivo de logs crudos, motor de búsqueda y base transaccional. | Consultas de búsqueda de logs sobre PostgreSQL colapsan el I/O con millones de registros. Sin particionado automático ni retención ISM. | Rediseñar PostgreSQL exclusivamente como plano transaccional (Tenants, Usuarios, Agentes, Reglas, Alertas, Incidentes, Auditoría). |
| **Motor de Búsqueda** | **INEXISTENTE** (Simulado en SQL sobre `events`). | No escala para búsqueda de texto libre o aggregations complejas de SIEM. | Paginación SQL lenta en millones de filas. Sin data streams. | Desplegar **OpenSearch** con Data Streams, Mappings explícitos, Aliases y Políticas ISM (Hot/Warm/Cold). |
| **Almacenamiento Crudo** | Tabla SQL `raw_logs` / Disco local. | Pérdida de evidencia si el disco local falla. Alto costo de almacenamiento en DB. | Sin firma criptográfica SHA-256 de custodia, sin aislamiento S3. | Implementar almacenamiento en **MinIO / S3** para chunks crudos con metadatos de integridad SHA-256 y retención configurable. |
| **Parsers** | 13 módulos Python regex (`app/parsing/`). | Sin esquema uniforme (ECS/OCSF). Parsers frágiles ante variaciones de formato. | Falta soporte nativo para DirectAdmin, WatchGuard, Corero, Proxmox, PowerDNS/BIND, Imunify360, auditd, journald. | Estandarizar bajo modelo de datos ECS-compatible y crear parsers aislados con fixtures y pruebas unitarias. |
| **Motor de Correlación** | Worker Python (`engine_worker_loop.py` + `rule_engine_v2.py`). | Polling constante a PostgreSQL. Evaluación secuencial lenta de reglas. | Falta correlación temporal avanzada cross-source (ej. ModSecurity + PHP execution + Exim spam). | Reorganizar como motor reactivo impulsado por eventos desde el Bus con ventanas deslizantes e in-memory state. |
| **Multitenancy & RBAC** | **INEXISTENTE**. | **Fuga de datos entre clientes**: No existe el concepto de `tenant_id` en las tablas principales. Roles globales mínimos. | No soporta arquitectura multi-cliente para proveedores de hosting. | Implementar `tenant_id` estricto en todos los planos, aislando datos a nivel de API, OpenSearch, PostgreSQL y S3. |
| **Seguridad & Auditoría** | Autenticación básica JWT/APIKey. | Secretos expuestos en variables de entorno o valores por defecto. Sin auditoría de acciones del SIEM. | Configuración CORS rígida (`app/main.py`), sin CSRF/SSRF protection. | Implementar RBAC granular (20+ permisos), hashes seguros, auditoría completa (`audit_events`) y gestión de secretos. |
| **Pruebas Automatizadas** | **ZERO PRUEBAS (0%)**. | Cualquier cambio rompe funcionalidades silenciosamente. | Imposibilidad de validar regresiones sin ejecución manual. | Desarrollar suite de pruebas automatizadas (pytest) unitarias, de integración, aisladas por tenant y de rendimiento. |

---

## 4. Vector de Pérdida de Eventos Identificado

Durante el análisis del código del agente (`agent/sentinelx-agent.sh`) y del pipeline (`app/services/log_pipeline.py`), se hallaron los siguientes vectores críticos de pérdida de datos:

1. **Purga Automática del Agente**:
   En `sentinelx-agent.sh` (líneas 62-66 y 130-135):
   ```bash
   RESET_ON_BACKEND_DOWN="${SENTINELX_RESET_ON_BACKEND_DOWN:-1}"
   RESET_ON_SEND_FAILURE="${SENTINELX_RESET_ON_SEND_FAILURE:-1}"
   ```
   Si la API de SentinelX se encuentra fuera de servicio (502/503/429/connection refused), el agente ejecuta `reset_for_next_run_due_to_failure`, eliminando **todos los archivos en el spool** (`rm -rf /var/spool/sentinelx-agent/*`) y borrando los archivos `.state` que registraban los inodos y offsets. Esto causa que todos los logs no enviados se pierdan definitivamente.

2. **Aborto por Umbral de Errores de Parseo**:
   En `app/services/log_pipeline.py` (líneas 387-391):
   ```python
   if lines_failed >= MAX_LINE_ERRORS:
       raise RuntimeError(f"Too many line errors: {lines_failed}")
   ```
   Un archivo de log grande con más de 5,000 líneas corruptas o no reconocidas provoca una excepción que revierte la transacción completa (`db.rollback()`), dejando el archivo en estado `error` y descartando todos los eventos válidos procesados previamente en ese lote.

3. **Inexistencia de Confirmación y Dead-Letter Queue (DLQ)**:
   Al no existir un bus de eventos entre la API de ingesta y los workers, cualquier fallo de base de datos durante la ejecución de los workers invalida el procesamiento sin un mecanismo de reintento duradero con DLQ.

---

## 5. Vulnerabilidades de Seguridad Halladas

1. **Ausencia de Multitenancy**: Todas las búsquedas de logs y eventos en los routers de FastAPI retornan resultados globales. No existe aislamiento de datos por cliente/tenant.
2. **Exposición CORS Hardcoded**: `origins` en `app/main.py` contiene dominios fijos (`https://sentinelx.tokyo-03.com`), lo cual es inapropiado para despliegues personalizados.
3. **Payloads y Bomba Gzip**: El endpoint `/logs/upload` acepta archivos de hasta 1GB sin validación de descompresión segura en streaming ni límites de cuota por agente o tenant.
4. **Secretos e Integraciones**: Ausencia de cifrado de secretos en reposo para claves de API o integraciones externas.

---

## 6. Siguiente Paso

Se presentará el **Plan de Implementación** integral para aprobación del usuario antes de iniciar cualquier modificación en el código.
