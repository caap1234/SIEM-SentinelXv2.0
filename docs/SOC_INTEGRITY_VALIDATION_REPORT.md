# SOC Integrity Validation Report
> **SentinelX SIEM** | Fecha: 2026-08-10 | Estado: ✅ VALIDADO

---

## Resumen Ejecutivo

Esta validación cubre las tres correcciones de integridad en el flujo SOC identificadas por el analista:

| # | Área | Problema | Corrección | Estado |
|---|------|----------|-----------|--------|
| 1 | Threat Hunting (OpenSearch) | El parámetro `?q=_id:<id>` mostraba todos los eventos en lugar del específico | Implementado soporte exacto para `_id:` e `event.id:` en el router y fallback de desarrollo | ✅ CORREGIDO |
| 2 | Evidencia MinIO S3 | Sin validación de integridad SHA-256 por referencia cruzada | Validado aislamiento por `tenant_id` y verificación SHA-256 con detección de tampering | ✅ VALIDADO |
| 3 | Generación PDF de Reportes | PDF generaba error "Failed to load PDF document" porque almacenaba HTML con extensión `.pdf` | Corregidas las 6 plantillas HTML (sin `var(--...)` ni `grid`), y `reporting_service.py` ahora valida cabecera `%PDF-` | ✅ CORREGIDO |

---

## 1. Threat Hunting — Búsqueda Exacta por Event ID

### Problema Raíz
Las plantillas de incidentes y alertas generaban URLs del tipo `/dashboard/hunting?q=_id:<event_id>`. El router `hunting.py` sí añadía la cláusula `{"ids": {"values": [id]}}` al `bool.filter` pero el fallback de desarrollo (cuando OpenSearch no está disponible) devolvía los 3 eventos mock sin filtrar.

### Correcciones Aplicadas

**`app/routers/hunting.py`:**
- Agregado tracking de `exact_event_id` para `_id:<val>` y `event.id:<val>`.
- Para `_id:` → usa cláusula `{"ids": {"values": [target_id]}}` en OpenSearch.
- Para `event.id:` → usa cláusula `{"bool": {"should": [{"term": {"event.id": val}}, {"term": {"event.id.keyword": val}}]}}`.
- En el fallback de desarrollo: filtra los eventos mock por `_id` y `event.id`. Si el ID no está en el catálogo mock, devuelve un **placeholder** con ese ID exacto para confirmar que el enlace funciona correctamente.

**`front/src/pages/dashboard/hunting.astro`:**
- Añadido banner contextual (naranja) que aparece cuando se llega al Threat Hunting desde un enlace de incidente/alerta con un filtro preactivo.
- Añadido listener `keydown` para ejecutar búsqueda al presionar `Enter`.

### Resultado
```
Incidente → Alerta → opensearch_event_id → URL → Threat Hunting → Devuelve SOLO ese evento
```

---

## 2. Evidencia MinIO S3 — Integridad y Aislamiento

### Validaciones Confirmadas

| Validación | Resultado |
|-----------|-----------|
| `tenant_id` en `s3_key` (prefix check) | ✅ Rechaza claves de otros tenants con `403 Access Denied` |
| Acceso admin a cualquier tenant | ✅ Permitido (`tenant_id == "admin"`) |
| Verificación SHA-256 de bytes recuperados | ✅ Calculado vs. esperado (metadata del objeto) |
| Detección de tampering | ✅ Hash mismatch detectado y logueado |
| Formato de clave S3 | ✅ `{tenant}/{year}/{month}/{day}/{source}/{event_id}.raw.gz` |

### Flujo de Enlace
```
Alerta/Incidente → s3_key → /dashboard/evidence?search=<s3_key>
→ Filtra catálogo → Abre el objeto exacto → Verifica SHA-256
```

---

## 3. Generación PDF de Reportes SOC

### Causa Raíz del Fallo
`xhtml2pdf` / ReportLab **no soporta**:
- Variables CSS `var(--nombre)` → `ValueError: Invalid color value '<css function: var(--border)>'`
- `display: grid` / `display: flex` (ignorados silenciosamente)

Al fallar `pisa.CreatePDF()`, el código anterior guardaba el HTML plano con extensión `.pdf` → el navegador lo rechazaba.

### Correcciones Aplicadas

**Plantillas HTML (`templates/reports/`):**

| Plantilla | Acción |
|----------|--------|
| `executive_weekly.html` | ✅ Reemplazados todos `var(--...)` por hex directos. Grid → tabla |
| `executive_monthly.html` | ✅ Ídem |
| `executive_quarterly.html` | ✅ Ídem |
| `soc_operational.html` | ✅ Ídem |
| `trends.html` | ✅ Ídem |
| `incident_report.html` | ✅ Ídem. Timeline con `<div>` en lugar de `<ul>::before` pseudo-elementos |

**`app/services/reporting_service.py`:**
- Genera el PDF en un `BytesIO` buffer primero.
- Valida que el resultado comience con `b"%PDF"`.
- Si falla o el resultado es inválido → lanza `RuntimeError` con mensaje descriptivo.
- Ya **no** guarda HTML silenciosamente con extensión `.pdf`.

### Verificación Manual
```bash
$ python -c "
from app.db import SessionLocal
from app.services.reporting_service import ReportingService
db = SessionLocal()
svc = ReportingService(db, tenant_id='default', created_by='admin@test.com')
r = svc.generate_report('executive_weekly', fmt='pdf', days=7)
with open(r.meta['local_file_path'], 'rb') as f:
    print(f.read(20))
# Output: b'%PDF-1.4\n%\x93\x8c\x8b\x9e Repor'  ← PDF VÁLIDO
"
```

---

## 4. Pruebas Automatizadas

**Archivo:** [`tests/unit/test_soc_integrity.py`](file:///Users/neubox/Projects/SentinelX-SIEM/tests/unit/test_soc_integrity.py)

### Resultados: 16/16 ✅

#### Threat Hunting (`TestThreatHuntingExactMatch`)
- ✅ `test_exact_match_by_internal_id` — `_id:evt-mock-001` devuelve 1 evento
- ✅ `test_exact_match_by_event_id_field` — `event.id:evt-mock-002` devuelve 1 evento  
- ✅ `test_nonexistent_event_returns_placeholder` — ID no existente → placeholder
- ✅ `test_no_filter_returns_all_events` — Sin filtro → todos los eventos
- ✅ `test_query_string_prefix_detection` — Detección correcta de `_id:` vs `event.id:` vs query libre

#### Evidencia MinIO S3 (`TestMinIOEvidenceIntegrity`)
- ✅ `test_tenant_isolation_rejects_cross_tenant_access`
- ✅ `test_tenant_isolation_allows_own_key`
- ✅ `test_admin_can_access_any_tenant_evidence`
- ✅ `test_sha256_integrity_verification` — SHA-256 calculado == esperado
- ✅ `test_sha256_tampered_data_detected` — Tampering detectado correctamente
- ✅ `test_s3_key_structure_validation`

#### Reportes PDF (`TestPDFReportGeneration`)
- ✅ `test_pdf_generation_produces_valid_binary` — Header `%PDF-1.4` verificado
- ✅ `test_pdf_fails_gracefully_with_css_vars`
- ✅ `test_executive_weekly_template_generates_valid_pdf` — Plantilla real + datos reales
- ✅ `test_incident_report_template_generates_valid_pdf` — Plantilla real + datos reales
- ✅ `test_reporting_service_pdf_no_longer_saves_html_as_pdf` — Lanza `RuntimeError` correctamente

---

## 5. Resultados de Build y Check

```
pytest:       113 passed, 0 failed, 17 warnings  ✅
npm run check: 0 errors, 0 warnings, 21 hints     ✅
npm run build: 18 pages built in 1.13s             ✅
```

---

## 6. Arquitectura de Almacenamiento — Sin Cambios

| Motor | Datos | Estado |
|-------|-------|--------|
| PostgreSQL | Alertas, Incidentes, Timeline, Reportes (metadata), Entidades | ✅ Intacto |
| OpenSearch | Eventos ECS normalizados, Threat Hunting, agregaciones | ✅ Intacto |
| MinIO S3 | Logs originales comprimidos, evidencia SHA-256, reportes PDF | ✅ Intacto |

> **No se alteró el pipeline de detección**: Ingestión → OpenSearch → Alertas → Incidentes → Timeline → Evidencia MinIO funcionan sin modificaciones.
