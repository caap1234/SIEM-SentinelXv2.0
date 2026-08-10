# Documento de Diseño Técnico — Módulo de Reportes SOC (SentinelX SIEM)

**Fecha**: 10 de Agosto, 2026  
**Versión**: 2.1.0-Enterprise  
**Estado**: Implementado y Validado  

---

## 1. Visión General de Arquitectura de Almacenamiento

El módulo de Reportes SOC respeta de forma estricta la separación de almacenamiento por motores sin duplicidad de logs masivos:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             MÓDULO DE REPORTES SOC                               │
└──────────────────────────────────────────────────────────────────────────────────┘
       │                                   │                                  │
       ▼                                   ▼                                  ▼
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│  PostgreSQL (Metadatos) │   │  OpenSearch (Analítica) │   │ MinIO S3 (Almacenamiento│
├─────────────────────────┤   ├─────────────────────────┤   │    de Archivos PDF/HTML)│
│ • Tabla `reports`       │   │ • Conteo de eventos ECS │   ├─────────────────────────┤
│ • Metadatos de reportes │   │ • Tendencias y agregaciones│ • Archivos renderizados│
│ • Periodos y parámetros │   │ • Búsquedas agregadas   │   │   PDF / HTML / JSON / CSV│
│ • Usuario creador       │   │                         │   │ • Logs raw inmutables   │
│ • Tenant ID             │   │                         │   │ • Hashes SHA-256        │
└─────────────────────────┘   └─────────────────────────┘   └─────────────────────────┘
```

---

## 2. Esquema de Tabla de Metadatos (`reports` en PostgreSQL)

PostgreSQL **únicamente** almacena información ligera de auditoría y metadatos:

```sql
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    type VARCHAR(64) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    format VARCHAR(16) NOT NULL DEFAULT 'pdf',
    storage_path TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'completed',
    meta JSONB NOT NULL DEFAULT '{}'
);
```

---

## 3. Tipos de Reportes Soportados

1. **Ejecutivo Semanal (`executive_weekly`)**:
   - Resumen para Dirección: volumen de eventos procesados, alertas por severidad, incidentes creados/resueltos, MTTR promedio, top 5 reglas activadas y top 5 entidades de mayor riesgo.
2. **Ejecutivo Mensual (`executive_monthly`)**:
   - Comparativas vs mes anterior con variaciones porcentuales (%), evolución de severidad y tendencias de volumen.
3. **Ejecutivo Trimestral (`executive_quarterly`)**:
   - Visión estratégica a 90 días con recomendaciones de seguridad y promedios mensuales.
4. **Operativo SOC (`soc_operational`)**:
   - Métricas detalladas para analistas: alertas nuevas/resueltas, incidentes en investigación/cerrados, falsos positivos y cumplimiento de SLAs.
5. **Reporte de Tendencias (`trends`)**:
   - Comparativa de variación porcentual en períodos móviles.
6. **Expediente Individual de Incidente (`incident_report`)**:
   - Dossier de investigación forense completo: resumen del incidente, alertas asociadas, eventos correlacionados, entidades involucradas, Timeline SOC cronológico, punteros a OpenSearch, referencias a objetos en MinIO S3 con sus hashes SHA-256 inmutables y la conclusión de investigación.

---

## 4. Seguridad, RBAC e Aislamiento Multitenant

- **Filtro Infranqueable por `tenant_id`**: Todas las consultas a PostgreSQL y OpenSearch inyectan el `tenant_id` del usuario autenticado.
- **Rutas de Almacenamiento Seguras en MinIO S3**:
  - `reports/{tenant_id}/{yyyy}/{mm}/report_{type}_{timestamp}.{format}`
- **Descargas Protegidas**: El endpoint `GET /api/v1/reports/{id}/download` valida el `tenant_id` del token JWT antes de transmitir el binario.

---

## 5. Estrategia de Formatos

- **PDF**: Formato ejecutivo oficial imprimible.
- **HTML**: Renderizado interactivo con Jinja2 y hojas de estilo SentinelX.
- **JSON**: Exportación de datos estructurados para integraciones externas.
- **CSV**: Métricas consolidadas en texto plano.
- **Exportación Técnica ZIP/CSV**: Se mantiene de forma independiente en `/admin/maintenance/exports` para análisis forense profundo de logs.
