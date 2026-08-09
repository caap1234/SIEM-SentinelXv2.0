# Guía de Operación y Configuración de MinIO S3 - SentinelX SIEM

## 1. Estructura de Objetos de Evidencia

Bucket Principal: `sentinelx-evidence`

```text
sentinelx-evidence/
├── tenant-default/
│   └── 2026/
│       └── 08/
│           └── 09/
│               └── exim_mainlog/
│                   └── 3b2a1c09-8f4e-4e1a-9f56-01a2b3c4d5e6.json.gz
```

### Metadatos Forenses por Objeto (`s3:GetObject` Metadata):
- `event_id`: ID único del evento.
- `sha256`: Hash SHA-256 del contenido original sin comprimir.
- `tenant_id`: Identificador de tenant.
- `timestamp`: Timestamp ISO 8601 UTC.
- `source`: Dataset de origen.
- `hostname`: Host de origen.
- `uncompressed_bytes`: Tamaño original.
- `compressed_bytes`: Tamaño comprimido en disco.

---

## 2. Diagnóstico y Consola Web

- **Endpoint API S3**: `http://localhost:9000`
- **Consola Web MinIO**: `http://localhost:9001` (Credenciales dev: `minioadmin` / `minioadmin`)

### Verificación por CLI (`mc` client):
```bash
# Configurar alias local
mc alias set local http://localhost:9000 minioadmin minioadmin

# Listar buckets y evidencia
mc ls local/sentinelx-evidence/

# Inspeccionar metadatos e integridad SHA-256 de una evidencia
mc stat local/sentinelx-evidence/tenant-default/2026/08/09/exim_mainlog/*.json.gz
```
