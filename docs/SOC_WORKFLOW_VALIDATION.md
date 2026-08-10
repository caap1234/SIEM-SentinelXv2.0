# Reporte de Validación del Flujo Operativo SOC — SentinelX SIEM

**Fecha de Validación**: 10 de Agosto, 2026  
**Estado**: Validado Exitosamente (Cadena SOC Operativa Completa 100%)

---

## 1. Visión General del Flujo Operativo SOC

Se ha verificado la integración punta a punta de la cadena de análisis e investigación de seguridad:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Log / Ingestión │ ────► │ OpenSearch (ECS)│ ────► │Alerta PostgreSQL│ ────► │ Incidente SOC   │ ────► │ MinIO S3 (Raw)  │ ────► │  Timeline SOC   │
│ (NATS Stream)   │       │(Event Reference)│       │(opensearch_id)  │       │(INC-SEC-01)     │       │(s3_key / SHA)   │       │  (Histórico)    │
└─────────────────┘       └─────────────────┘       └─────────────────┘       └─────────────────┘       └─────────────────┘       └─────────────────┘
```

---

## 2. Puntos de Validación Realizados

### 2.1 Alertas ➔ OpenSearch & MinIO S3
- **Generación Automática**: En [rule_engine_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/services/rule_engine_v2.py), cada nueva alerta registrada en PostgreSQL extrae y almacena:
  - `opensearch_event_id`: Identificador único del evento gatillador en OpenSearch.
  - `s3_key`: Ruta relativa del archivo comprimido `.json.gz` en MinIO S3.
- **Navegación en Frontend ([alertas.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/alertas.astro))**:
  - Botón **"Investigar eventos relacionados"** ➔ Redirige a `/dashboard/hunting?q=_id:<opensearch_event_id>`.
  - Botón **"Ver Log Original en MinIO (S3)"** ➔ Recupera el contenido inmutable en MinIO S3 y valida su hash SHA-256.

### 2.2 Incidentes ➔ Evidencias Duales y Trazabilidad (Alerta + Incidente)
- **Trazabilidad Completa**: La relación de evidencias coexiste en dos niveles sin destruirse:
  - **Evidencia de Alertas**: Mantiene los campos `s3_key` y `opensearch_event_id` por cada alerta vinculada al incidente.
  - **Evidencia de Incidente**: Permite al analista adjuntar archivos, notas o registros forenses adicionales directamente al incidente vía `POST /incidents/{id}/notes` o metadatos de evidencia.
- **Vista de Detalle ([incidentes.astro](file:///Users/neubox/Projects/SentinelX-SIEM/front/src/pages/dashboard/incidentes.astro))**:
  - Visualización de **Alertas Relacionadas** con enlaces directos a OpenSearch y S3.
  - Visualización de **Entidades Relacionadas** (IPs, usuarios, hosts) con su nivel de riesgo.
  - Accesos directos a **Threat Hunting** y **Explorador de Evidencias en MinIO**.

### 2.3 Timeline SOC Automático ([incidents_v2.py](file:///Users/neubox/Projects/SentinelX-SIEM/app/routers/incidents_v2.py))
- Registro cronológico de acciones:
  1. **Creación de Incidente**: Registro inicial con marca temporal y entidad primaria.
  2. **Alertas Vinculadas**: Historial de cada alerta que compone el incidente.
  3. **Notas del Analista**: Registro de comentarios, hallazgos o justificaciones con autor y timestamp.
  4. **Cambios de Estado**: Auditoría de transiciones (`open` ➔ `in_investigation` ➔ `resolved` / `false_positive`).

### 2.4 Validación de Cierre e Inmutabilidad del Historial
- Al resolver o cerrar un incidente (`resolved`, `false_positive`, `closed_by_incident`):
  - **Alertas Preservadas**: Las alertas no se eliminan de PostgreSQL; cambian su estado a `closed_by_incident`.
  - **Entidades Preservadas**: Las entidades conservan su puntuación y ciclo de vida independiente.
  - **Historial Intacto**: El Timeline y la evidencia asociada permanecen inmutables para auditorías futuras.

---

## 3. Pruebas Automatizadas y Compilación

| Prueba | Comando | Resultado |
|---|---|---|
| **Backend Unit & Integration Tests** | `pytest --no-header -q` | **97 PASSED** (100% Exitoso) |
| **Frontend TypeScript Check** | `npm run check` | **0 Errors, 0 Warnings** |
| **Frontend Build** | `npm run build` | **Build Exitoso** (17 rutas estáticas generadas) |


---

## 4. Conclusión

El flujo operativo SOC está completamente validado y conectado. La arquitectura garantiza la trazabilidad entre el evento en tiempo real en OpenSearch, la evidencia inmutable en S3, la alerta y el incidente en PostgreSQL, y la auditoría cronológica en el Timeline SOC.
