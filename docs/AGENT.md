# SentinelX Agent - Guía de Arquitectura, Despliegue y Operación

## 1. Arquitectura y Principios del Agente

El **SentinelX Agent** (`sentinelx-agent.sh`) es un componente liviano instalado directamente en cada servidor Linux monitoreado (AlmaLinux, CloudLinux, cPanel/WHM, DirectAdmin, Ubuntu, Debian).

### Principios Fundamentales:
1. **Conexiones Salientes Exclusivas**: El agente se comunica con la API central del SIEM mediante solicitudes HTTPS / mTLS **únicamente en dirección saliente** (Outbound). No requiere puertos abiertos ni servicios escuchando en los servidores monitoreados.
2. **Seguimiento por Inodo y Offset**: Mantiene un estado atómico por cada archivo observado en `/var/lib/sentinelx-agent/*.state` registrando `(inode, offset)`. Sobrevive a rotaciones de logs (`logrotate`, `copytruncate`, recreación de archivos).
3. **Spool Persistente Local con Garantía de Retención**: Ante caídas del backend, respuestas HTTP 429/5xx, timeouts o pérdidas de conectividad, el agente **PRESERVA** todo el buffer en `/var/spool/sentinelx-agent/` y NO elimina datos (`RESET_ON_BACKEND_DOWN=0`).
4. **Máquina de Estados Integrada**: Reporta su salud interna mediante `/var/lib/sentinelx-agent/agent_state.json`:
   - `healthy`: Operación normal y comunicación exitosa.
   - `delayed`: Transmisión en progreso con retraso o backend degradado (5xx/429).
   - `offline`: Sin conectividad de red hacia la API del SIEM.
   - `spool_warning`: Ocupación de spool entre 500 MB y 1 GB.
   - `spool_critical`: Ocupación de spool mayor a 1 GB.
   - `authentication_failed`: Error 401/403 en API Key o certificado.
   - `configuration_error`: Faltan variables de entorno requeridas.

---

## 2. Requisitos de Red y Conectividad

- **Dirección**: Únicamente saliente (Host Monitoreado ➔ SIEM Central).
- **Protocolo**: HTTPS (Puerto 443 o 8000) o mTLS (TLS 1.3 con certificados mutuos).
- **Reglas de Firewall (Egress)**: Permitir salida desde la IP del servidor hacia `https://siem.empresa.com:443`.
- **Infraestructura Requerida**:
  - Sin cambios de rutas o VLANs.
  - Sin bridges ni modo promiscuo.
  - Sin necesidad de NAT especial ni interceptación de tráfico.
  - Sin puertos de entrada en los servidores cPanel/DirectAdmin.

---

## 3. Recolección Opcional de Métricas de Host

El agente incluye un recolector liviano configurable para monitorear recursos de infraestructura sin interferir con los servicios de hosting:

```text
CPU / Load Average / Memory / Swap:  cada 30 a 60 segundos
Disco / Inodos / IOPS:               cada 5 minutos
Exim Queue / Dovecot Sessions:      cada 1 a 5 minutos
```

Las métricas se emiten con formato JSON estructurado hacia el dataset `metrics.sentinelx.system` y pueden deshabilitarse mediante la variable `SENTINELX_COLLECT_METRICS=0`.

---

## 4. Instalación y Configuración

```bash
# Variables de entorno base (/etc/sentinelx-agent.env)
SENTINELX_INGEST_URL="https://siem.tuempresa.com/logs/ingest"
SENTINELX_API_KEY="sx_agent_key_xxxxxxxx"
SENTINELX_MODE="auto"
SENTINELX_CHUNK_MB=50
SENTINELX_RESET_ON_BACKEND_DOWN=0
SENTINELX_RESET_ON_SEND_FAILURE=0
SENTINELX_SPOOL_WARN_MB=500
SENTINELX_SPOOL_CRIT_MB=1024
```
