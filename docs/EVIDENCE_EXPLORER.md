# Arquitectura y Exploración de Evidencia Forense MinIO (S3)

## 1. Visión General

El **Explorador de Evidencia Forense** (`/dashboard/evidence`) proporciona una vista de catálogo e inspección sobre el bucket inmutable de MinIO (S3). Garantiza la custodia forense y verificación de no alteración de los logs originales mediante el hash SHA-256.

---

## 2. Estructura de Almacenamiento S3 y Aislamiento por Tenant

La jerarquía de claves S3 cumple la convención estricta:
```text
sentinelx-evidence/{tenant_id}/{year}/{month}/{day}/{source}/{event_id}.raw.gz
```

- **Aislamiento por Tenant**: Las consultas están restringidas al prefijo `{tenant_id}/`. Intentos de acceder a claves de otros tenants devuelven `403 Forbidden` (`EvidenceAccessDeniedError`).

---

## 3. Endpoints Backend (`app/routers/evidence_explorer.py`)

- **`GET /api/v1/evidence/explore`**:
  - Lista los paquetes de evidencia `.raw.gz` en MinIO S3 bajo el prefijo del tenant.
  - **Permiso Requerido**: `ingest.read`

- **`GET /api/v1/evidence/object`**:
  - Descarga, descomprime mediante gzip y valida el hash SHA-256 del objeto indicado.
  - Retorna la verificación de integridad (`integrity_verified: true`) y el texto crudo del log.
  - **Permiso Requerido**: `ingest.read`
