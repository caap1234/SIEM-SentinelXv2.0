# Reporte de Migración e Implementación del Modelo de Almacenamiento — SentinelX SIEM

**Fecha de Ejecución**: 10 de Agosto, 2026  
**Estado**: Completado Exitosamente (100% Reversible y Validado)

---

## 1. Resumen Ejecutivo

En cumplimiento con el documento de diseño [STORAGE_ARCHITECTURE.md](file:///Users/neubox/Projects/SentinelX-SIEM/docs/STORAGE_ARCHITECTURE.md), se ha realizado la migración del esquema de almacenamiento de la tabla `alerts` en PostgreSQL para incorporar campos de referencia directa hacia OpenSearch (`opensearch_event_id`) y MinIO S3 (`s3_key`).

Esta mejora desacopla la carga de logs masivos de la base de datos relacional PostgreSQL, permitiendo que las alertas mantengan su estado y ciclo de vida de forma liviana mientras apuntan directamente al evento indexado en OpenSearch y a la evidencia original en S3.

---

## 2. Acciones Realizadas

### 2.1 Migración Alembic Reversible
- **Revisión**: `4e1ea9c89d5f_add_alerts_opensearch_event_id_and_s3_key`
- **Cambios Aplicados**:
  - Adición de columna `alerts.opensearch_event_id` (String(255), Nullable, Indexed).
  - Adición de columna `alerts.s3_key` (String(512), Nullable, Indexed).
  - Creación de índices B-Tree `ix_alerts_opensearch_event_id` e `ix_alerts_s3_key`.
- **Prueba de Reversibilidad**:
  - `alembic downgrade -1` ➔ **Exit Code 0** (Eliminación limpia de columnas e índices).
  - `alembic upgrade head` ➔ **Exit Code 0** (Re-aplicación limpia sin pérdida de datos).

### 2.2 Actualización del Modelo SQLAlchemy & API DTOs
- **[app/models/alert.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/models/alert.py)**: Declaración oficial de los atributos `opensearch_event_id` y `s3_key`.
- **[app/routers/alerts.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/alerts.py)**: Actualización de `AlertDetailResponse` y `get_alert` para exponer las referencias hacia la interfaz.

### 2.3 Integración en el Pipeline de Ingestión
- **[app/services/rule_engine_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/services/rule_engine_v2.py)**:
  - Al gatillarse una alerta a partir de un evento recibido de NATS/OpenSearch, se extraen y registran automáticamente los identificadores `opensearch_event_id` y `s3_key` en la nueva alerta de PostgreSQL.

---

## 3. Validación de Flujo del Pipeline

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Evento Recibido │ ────► │ OpenSearch (ECS)│ ────► │Alerta PostgreSQL│ ────► │ MinIO S3 (Raw)  │
│  (NATS Stream)  │       │(search event_id)│       │(opensearch_id)  │       │    (s3_key)     │
└─────────────────┘       └─────────────────┘       └─────────────────┘       └─────────────────┘
```

1. **Ingesta**: NATS Stream procesa el log normalizado.
2. **OpenSearch**: Indexa el documento ECS con ID único (`_id`).
3. **Regla de Detección**: El motor de correlación evalúa la ventana y crea la `Alert` en PostgreSQL asignando `opensearch_event_id = event_id` y `s3_key = path_in_minio`.
4. **Evidencia Forense**: MinIO S3 almacena el archivo comprimido `.json.gz` con su hash SHA-256 intacto.

---

## 4. Resultados de Pruebas Automatizadas

| Suite de Pruebas | Resultado | Detalles |
|---|---|---|
| **pytest** | **96 PASSED** (0 Fallas) | Validación limpia de API, modelos relacionales, parsers y motores de correlación |
| **npm run check** | **0 Errors, 0 Warnings** | Compilación TypeScript limpia de la interfaz frontend Astro |
| **npm run build** | **Completed in 1.02s** | Generación estática exitosa de las 17 páginas del portal |

---

## 5. Garantía de Integridad y Siguientes Pasos

- **Preservación de Datos**: No se eliminó ningún registro existente en PostgreSQL.
- **Frontend Preservado**: La experiencia de usuario y vistas actuales se mantienen idénticas.
- **Próximos Pasos**: Proceder con la implementación del Módulo de Reportes SOC y la interfaz de Política de Retención Automática.
