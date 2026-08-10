# Arquitectura del Modelo de Almacenamiento — SentinelX SIEM

## 1. Visión General y Principios de Diseño

SentinelX SIEM opera con una arquitectura de almacenamiento en **tres capas desacopladas**, diseñadas para garantizar alto rendimiento de ingesta, escalabilidad horizontal, cumplimiento de auditoría y respuesta SOC eficiente.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SentinelX SIEM Storage Model                                     │
└───────────────┬──────────────────────────────────┬────────────────────────────────┬──────────────┘
                │                                  │                                │
                ▼                                  ▼                                ▼
  ┌───────────────────────────┐      ┌───────────────────────────┐    ┌───────────────────────────┐
  │  Capas Transaccionales &  │      │  Motor Analítico & Bús-   │    │  Almacén Forense Inmu-    │
  │     Gestión de Estado     │      │   queda de Alto Volumen   │    │     table de Objetos      │
  │        [PostgreSQL]       │      │       [OpenSearch]        │    │        [MinIO S3]        │
  └─────────────┬─────────────┘      └─────────────┬─────────────┘    └─────────────┬─────────────┘
                │                                  │                                │
                ├─ Incidentes & Timeline           ├─ Eventos Normalizados ECS      └─ Raw Logs originales
                ├─ Alertas (Estado & Metadatos)    │  (sentinelx-events-*)             comprimidos (.json.gz)
                ├─ Entidades (Score Actual)        ├─ Historial de Riesgo             Firma SHA-256 inmutable
                ├─ Reglas de Detección             │  (sentinelx-entity-risk-*)        para auditoría forense.
                └─ Usuarios, API Keys & Config     └─ Métricas de Ingesta & EPS
```

---

## 2. Análisis del Estado Actual en PostgreSQL

### 2.1 Inspección de Tablas e Índices (Entorno Actual)

Una evaluación del motor transaccional de PostgreSQL muestra la distribución de almacenamiento y crecimiento:

| Tabla / Componente | Tamaño Total | Tamaño Datos | Tamaño Índices | Filas Est. | Descripción / Propósito |
|---|---|---|---|---|---|
| `rules_v2` | 136 kB | 40 kB | 96 kB | 57 | Reglas de detección activas y su configuración. |
| `alerts` | 96 kB | 8.2 kB | 88 kB | - | Estado de alertas, severidad, disposition y notas. |
| `agent_api_keys` | 88 kB | 8.2 kB | 80 kB | - | Claves API emitidas para agentes Linux. |
| `users` | 80 kB | 8.2 kB | 72 kB | - | Cuentas de usuarios y roles RBAC. |
| `registered_agents` | 80 kB | 8.2 kB | 72 kB | - | Inventario de agentes Linux registrados. |
| `entities` | 64 kB | 8.2 kB | 56 kB | - | Estado actual de entidades (IP, host, user) y score. |
| `incidents` | 64 kB | 8.2 kB | 56 kB | - | Fichas de incidentes, estado, score y notas SOC. |
| `incident_alerts` | 40 kB | 8.2 kB | 32 kB | - | Tabla pivote N:M entre incidentes y alertas. |
| `incident_entities` | 40 kB | 8.2 kB | 32 kB | - | Tabla pivote N:M entre incidentes y entidades. |
| `events_*` / `rawlogs_*` | 48 kB /c.u. | 0 bytes | 48 kB /c.u. | 0 | *Estrucutras legacy de particionado en PostgreSQL.* |

### 2.2 Hallazgos Clave
1. **Desacoplamiento de Logs Masivos**: Los registros masivos de eventos ya no se almacenan en PostgreSQL. Las tablas heredadas (`events_YYYY_MM_DD` y `rawlogs_YYYY_MM_DD`) permanecen como estructuras vacías y deben ser purgadas o deprecadas.
2. **Duplicación de Payloads en Alertas**: Actualmente, la columna `evidence` (JSONB) de la tabla `alerts` almacena muestras de logs o extractos completos. Para optimizar PostgreSQL, se deben almacenar referencias directas (`opensearch_event_id` y `s3_key`), evitando duplicar texto plano extenso en PostgreSQL.

---

## 3. Matriz de Separación Arquitectónica de Datos

| Componente | PostgreSQL (Transaccional) | OpenSearch (Analítico & Búsqueda) | MinIO S3 (Evidencia Inmutable) |
|---|---|---|---|
| **Eventos Recibidos** | Ninguno (0 logs masivos en DB) | Índice `sentinelx-events-YYYY.MM.DD` (Búsqueda en milisegundos para Threat Hunting) | Objeto `tenant/YYYY/MM/DD/dataset/event_id.json.gz` con SHA-256 |
| **Alertas** | Estado (`open`/`closed`), severidad, disposition, `opensearch_event_id`, `s3_key` | Ninguno (búsqueda indirecta por event_id) | Referencia al log original trigger |
| **Entidades** | Estado actual (`entity_type`, `entity_key`, `score_current`, `severity`) | Historial de evolución de riesgo (`sentinelx-entity-risk-YYYY.MM`) | N/A |
| **Incidentes** | Ficha de incidente (`INC-SEC-01`), estado, score, notas de analista, pivotes N:M | Ninguno | N/A |
| **Timeline SOC** | Referencias estructuradas (`timestamp`, `user`, `action`, `alert_id`, `s3_key`) | Múltiples eventos correlacionados | Objetos asociados |

---

## 4. Diseño Detallado por Componente

### 4.1 Módulo de Alertas (`alerts`)
- **En PostgreSQL**:
  - Mantiene el ciclo de vida operacional: `status` (`new`, `in_investigation`, `resolved`, `false_positive`, `closed_by_incident`), `disposition`, `resolution_note`, `resolved_at`, `resolved_by`.
  - Atributos relacionales: `rule_id`, `rule_name`, `severity`, `server`, `source`, `event_type`, `group_key`, `triggered_at`.
  - **Referencia Ligera**: `opensearch_event_id` (String) y `s3_key` (String).
- **Evición de Carga**: No se almacena el JSON/Raw Log completo en PostgreSQL `evidence`. En su lugar, el cliente web solicita los datos bajo demanda llamando al API que consulta OpenSearch o MinIO S3.

### 4.2 Módulo de Eventos (`events` / `rawlogs`)
- **En OpenSearch**:
  - Todo evento procesado por el pipeline de ingestión se indexa en esquemas ECS en `sentinelx-events-YYYY.MM.DD`.
  - Habilita agregaciones complejas por tipo de ataque, volumen por servidor, origen geográfico e IP.
- **En PostgreSQL**:
  - **Cero registros de eventos masivos**.

### 4.3 Módulo de Entidades (`entities`)
- **En PostgreSQL**:
  - Guarda la vista del estado actual de cada entidad: `entity_type` (`ip`, `user`, `host`), `entity_key` (`198.51.100.45`), `score_current` (0..100), `severity` (`critical`, `high`, `clean`), `first_seen_at`, `last_seen_at`.
- **En OpenSearch**:
  - Almacena el time-series de evolución de riesgo (`sentinelx-entity-risk-YYYY.MM`) para generar gráficas de tendencia histórica de riesgo por entidad a lo largo del tiempo.

### 4.4 Investigación SOC & Incidentes (`incidents`)
- **En PostgreSQL**:
  - Mantiene las fichas de incidentes (`incidents`), reglas de incidentes (`incident_rules`) y relaciones pivote (`incident_alerts` e `incident_entities`).
  - Almacena el **Timeline de Investigación SOC** y las **Notas del Analista** en la columna `evidence` (JSONB estructurado ligero).

---

## 5. Estrategia de Indexación y Estimación de Rendimiento en PostgreSQL

### 5.1 Estimación de Tráfico y Operaciones
- **Lecturas de Dashboard / SOC**: ~120 peticiones/minuto (APIs de consulta de incidentes, alertas y KPIs).
- **Escrituras en Ingestión (Alertas & Entidades)**:
  - Promedio: ~30-100 alertas activadas/minuto en escenarios de ataque.
  - Actualización de Entidades: ~50-200 updates/minuto.
- **Ventaja**: Al desviar el 100% de los logs masivos a OpenSearch y MinIO S3, la base de datos PostgreSQL se mantiene ligera (< 500 MB para años de datos transaccionales), eliminando la degradación por crecimiento descontrolado de tablas.

### 5.2 Índices Recomendados en PostgreSQL
```sql
-- Alertas
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_opensearch_event_id ON alerts(opensearch_event_id);

-- Entidades
CREATE INDEX IF NOT EXISTS idx_entities_tenant_type_key ON entities(tenant_id, entity_type, entity_key);
CREATE INDEX IF NOT EXISTS idx_entities_score ON entities(score_current DESC);

-- Incidentes
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_last_activity ON incidents(last_activity_at DESC);
```

---

## 6. Recomendaciones para Fases Futuras
1. **Paso a Producción**: Agregar las columnas `opensearch_event_id` y `s3_key` a la tabla `alerts` mediante una migración de Alembic en etapas posteriores.
2. **Depreciación de Particiones Legacy**: Eliminar las tablas particionadas vacías `events_*` y `rawlogs_*` en PostgreSQL para mantener el esquema relacional pulcro.
3. **Historial de Entidades en OpenSearch**: Activar un worker liviano que publique instantáneas de cambio de score de entidad hacia OpenSearch `sentinelx-entity-risk-*`.
