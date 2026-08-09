# Requisitos de Red y Conectividad - SentinelX SIEM

## 1. Topología de Red de la Plataforma

```text
[ Servidor Linux cPanel / DirectAdmin #1 ] ──(HTTPS/mTLS Saliente: 443/8000)──┐
[ Servidor Linux cPanel / DirectAdmin #2 ] ──(HTTPS/mTLS Saliente: 443/8000)──┼──> [ SentinelX API Ingesta ]
[ Servidor Linux cPanel / DirectAdmin #N ] ──(HTTPS/mTLS Saliente: 443/8000)──┘
```

---

## 2. Requisitos para Servidores Monitoreados (Agentes)

| Parámetro | Valor / Regla |
| :--- | :--- |
| **Dirección del Tráfico** | **Exclusivamente Saliente (Egress)** |
| **Puertos Entrantes Requeridos** | **Ninguno (0 puertos abiertos en el servidor)** |
| **Protocolo de Transporte** | TLS 1.2 / TLS 1.3 |
| **Puerto Saliente Destino** | TCP 443 o TCP 8000 |
| **Host / FQDN Destino** | `ingest.sentinelx.empresa.com` |
| **Certificados** | CA pública (Let's Encrypt / DigiCert) o CA interna corporativa |
| **Consumo Estimado de Ancho de Banda** | 10 MB a 200 MB / día por host (según volumen de logs y compresión gzip) |
| **Sincronización de Tiempo** | **NTP obligatorio** (desfase máximo permitido: 5 segundos) |

---

## 3. Integraciones Perimetrales (WatchGuard / Corero)

- **WatchGuard Firebox / Dimension**: Syslog TLS (TCP 6514) o Syslog UDP 514 dirigido hacia los colectores centrales de SentinelX.
- **Corero SmartWall**: Integración vía API REST HTTPS o Syslog TLS (TCP 6514).

---

## 4. Política de Reintentos y Resiliencia de Red

- **Connect Timeout**: 10 segundos.
- **Max Request Duration**: 7200 segundos (para chunks grandes de hasta 50MB).
- **Backoff Exponencial**: Reintentos automáticos con jitter (1s ➔ 2s ➔ 4s ➔ 8s ➔ max 300s).
- **Comportamiento ante Pérdida de Conexión**: Los datos se almacenan en la cola spool local (`/var/spool/sentinelx-agent/`) hasta restablecer la comunicación con la API del SIEM.
