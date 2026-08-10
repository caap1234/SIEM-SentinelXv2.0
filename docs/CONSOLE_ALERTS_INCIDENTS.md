# Consola de Alertas e Incidentes con Evidencia Forense (MinIO S3)

## 1. Visión General

La consola de Alertas e Incidentes de SentinelX SIEM proporciona el flujo completo de respuesta ante incidentes para operadores y analistas SOC:
1. **Detección y Correlación**: Visualización de alertas disparadas por las 10 reglas de hosting (Exim, Dovecot, WordPress, SSH, ModSecurity, Imunify360, auditd).
2. **Inspección de Evidencia Forense**: Verificación de inmutabilidad y recuperación directa de paquetes de evidencia cruda desde MinIO (S3) mediante la firma Hash SHA-256.
3. **Gestión de Ciclo de Vida**: Cambio de estados individual y masivo (`open`, `resolved`, `false_positive`, `triage`, `contained`, `closed`) con soporte de cascada entre incidentes y sus alertas asociadas.

---

## 2. Endpoints Backend Integrados

- **`GET /api/v1/alerts`**: Lista paginada y filtrada de alertas asociadas al `tenant_id` del usuario.
- **`GET /api/v1/alerts/{id}`**: Detalle de alerta, incluyendo métricas y snippet de log original.
- **`GET /api/v1/alerts/{id}/evidence`**: Recupera el objeto de evidencia forense almacenado en MinIO (S3), valida la firma SHA-256 y entrega el contenido descomprimido.
- **`PATCH /api/v1/alerts/status/bulk`**: Actualización masiva de estado para alertas seleccionadas.
- **`GET /api/v1/incidents`**: Lista de incidentes agrupados con su score de riesgo y contadores de alertas.
- **`PATCH /api/v1/incidents/{id}/status?cascade=true`**: Cambio de estado de un incidente con opción de propagar la resolución a todas las alertas dependientes.

---

## 3. Flujo de Trabajo SOC y Evidencia S3

```text
[Alerta / Incidente Disparado] 
          |
          v
[Consola Frontend Astro JS] ---> [Modal de Inspección] 
                                      |
                                      +---> [Botón "Ver Evidencia Forense MinIO S3"]
                                                  |
                                                  v
                                    [GET /alerts/{id}/evidence]
                                                  |
                                                  v
                                    [MinIO S3 Download & SHA-256 Check]
                                                  |
                                                  v
                                    [Log Crudo Inmutable & Firma Forense]
```
