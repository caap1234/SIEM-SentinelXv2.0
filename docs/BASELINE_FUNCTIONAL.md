# Línea Base Funcional (v0.2.0) - SentinelX SIEM

## 1. Descripción General de la Línea Base Funcional

Este documento describe la capacidad funcional y el flujo de trabajo verificado de la versión legacy (v0.2.0) de **SentinelX-SIEM** previo al inicio de las transformaciones hacia la arquitectura empresarial objetivo.

---

## 2. Componentes y Flujos de Ejecución Verificados

### 2.1 Backend HTTP (API FastAPI)
- **Instanciación**: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **Endpoints de Ingesta**:
  - `/logs/upload` (Form-data multipart con autenticación JWT de usuario).
  - `/logs/ingest` (Form-data multipart con autenticación por `X-API-Key` de servidor).
- **Mapeo de Logs**: Mapeo directo de tags (`apache_access`, `exim_mainlog`, `modsec`, `maillog`, `lfd`, etc.) hacia tipos de log procesables por los parsers internos.

### 2.2 Agente de Recolección (sentinelx-agent.sh)
- **Ejecución**: Script Bash ejecutado periódicamente (cron/systemd timer).
- **Mecanismo de Lectura**: Seguimiento básico de inodo y offset almacenado en `/var/lib/sentinelx-agent/*.state`.
- **Compresión y Spool**: Almacena bloques temporales comprimidos en `/var/spool/sentinelx-agent`.
- **Fallo Identificado**: `RESET_ON_BACKEND_DOWN=1` elimina el spool en caso de error de conectividad (corregido en Fase 0.5).

### 2.3 Worker de Parseo (parsing_worker_loop.py)
- **Estrategia**: Polling periódico a la tabla PostgreSQL `log_uploads` buscando estado `queued`.
- **Bloqueo de Filas**: `SELECT id FROM log_uploads WHERE status = 'queued' FOR UPDATE SKIP LOCKED LIMIT 1`.
- **Parseo**: Ejecuta `parse_log_file()`, leyendo línea por línea y usando expresiones regulares.
- **Inserción**: Genera registros directos en las tablas `raw_logs` y `events` de PostgreSQL.

### 2.4 Worker de Correlación (engine_worker_loop.py)
- **Estrategia**: Polling periódico a la tabla PostgreSQL `events` buscando `engine_status = 'pending'`.
- **Motor de Reglas**: Ejecuta `RuleEngineV2` (`app/services/rule_engine_v2.py`).
- **Generación de Detecciones**: Crea registros en las tablas `alerts` e `incidents` de PostgreSQL.

### 2.5 Interfaz de Usuario (Astro Frontend)
- **Despliegue**: Aplicación frontend Astro servida en puerto `4321`.
- **Módulos**: Visualización de métricas de panel, listado de alertas, gestión de incidentes, estado de procesos y puntuación de riesgo por entidad.

---

## 3. Estado de la Persistencia Legada

Toda la persistencia reside en la base de datos PostgreSQL:
- `log_uploads`: Cola de ingesta de archivos.
- `raw_logs`: Líneas de texto crudo almacenadas en base de datos.
- `events`: Eventos normalizados preliminares.
- `alerts` e `incidents`: Alertas generadas por el motor de correlación.
- `users`, `api_keys`, `rules_v2`, `incident_rules`: Configuración y autenticación.
