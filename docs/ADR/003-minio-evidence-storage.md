# ADR 003: Almacenamiento de Evidencia Cruda e Inmutable mediante MinIO (S3)

- **Estado**: Aceptado
- **Fecha**: 2026-08-09
- **Autores**: Arquitecto Principal de Software & Especialista DevSecOps / Forense

---

## 1. Contexto y Problema

En auditorías de seguridad e investigaciones forenses de hosting masivo (incidentes en cPanel, Exim, ModSecurity), se requiere preservar la evidencia original de los eventos en su forma cruda de manera **inalterable, inmutable y verificable criptográficamente**.

Requisitos de diseño:
1. Almacenamiento jerárquico por tenant, año, mes, día y fuente.
2. Garantía de integridad mediante suma de verificación **SHA-256**.
3. Compresión eficiente mediante `gzip` (nivel 9) para reducir el almacenamiento en disco en un ~80%.
4. No bloqueo: si el cluster de MinIO / S3 se encuentra fuera de línea, la ingesta principal y la búsqueda en OpenSearch **NO deben detenerse**.
5. WORM (Write Once, Read Many) y separación por tenant.

---

## 2. Decisión Adoptada

Se adopta **MinIO (S3 Compatible)** como el repositorio oficial de evidencia cruda inmutable para **SentinelX-SIEM**.

### Estructura de Rutas en Bucket `sentinelx-evidence`:
`{tenant_id}/{YYYY}/{MM}/{DD}/{source}/{event_id}.json.gz`

### Garantías de Integridad Forense:
- **Hash SHA-256**: Cada paquete empaquetado registra en sus metadatos S3 (`Metadata['sha256']`) la firma SHA-256 de los datos originales sin comprimir.
- **Verificación al Descargar**: La función `retrieve_and_verify_evidence()` re-calcula el Hash SHA-256 al recuperar cualquier objeto y alerta inmediatamente en caso de discrepancia.

### Desacoplamiento de Ingesta vía NATS:
- El worker `MinioEvidenceWorker` consume de NATS JetStream de forma independiente.
- Si MinIO está fuera de línea, el worker **no confirma (ACK)** el mensaje a NATS JetStream. El broker retiene el mensaje en su cola persistente de disco hasta que MinIO recupere la conectividad.

---

## 3. Consecuencias

- **Positivas**:
  - Evidencia forense inalterable y respaldada para cumplimiento legal e investigaciones.
  - Cero impacto en la latencia p95 de la API de Ingesta.
  - Aislamiento total de almacenamiento por cliente/tenant.
