# Guía de Instalación y Configuración del Agente SentinelX SIEM

El **Agente SentinelX Linux** es un script Bash autónomo y ligero que recolecta logs de auditoría (`secure`, `auth.log`, `nginx`, `apache`, `cPanel`, `lfd`, `modsec`, `sar`) y métricas del sistema para transmitirlos de manera segura al servidor central SentinelX SIEM.

---

## 1. Requisitos Previos del Servidor Cliente

- **Sistema Operativo**: AlmaLinux / Rocky / CentOS / RHEL (7, 8, 9), Ubuntu (18.04, 20.04, 22.04, 24.04), Debian (10, 11, 12).
- **Herramientas de Sistema**: `bash`, `curl`, `grep`, `awk`, `python3` (para normalización local previa a envío).
- **Acceso**: Permisos de `root` en el servidor a monitorear.
- **Credenciales SIEM**: `SENTINELX_API_KEY` (generada en la interfaz del SIEM bajo `/dashboard/api-keys`).

---

## 2. Instalación en 1 Solo Paso

Ejecute el siguiente comando en el servidor cliente como `root`:

```bash
curl -fsSL https://raw.githubusercontent.com/caap1234/SentinelX-Neubox/refs/heads/main/agent/install_sentinelx_agent.sh | bash
```

Durante la instalación, el script le solicitará ingresar la **API Key de SentinelX SIEM**.

---

## 3. Configuración Manual (`/etc/sentinelx-agent.env`)

El archivo de configuración del agente se guarda en `/etc/sentinelx-agent.env` con permisos `600`:

```bash
# /etc/sentinelx-agent.env

# URL del endpoint de ingesta en el servidor SIEM
SENTINELX_INGEST_URL="https://tu-siem-domain.com/logs/ingest"

# API Key de autenticación
SENTINELX_API_KEY="sx_key_live_xxxxxxxxxxxxxxxx"

# Modo de recolección ("cpanel" | "directadmin" | "auto")
SENTINELX_MODE="auto"

# Días de logs a procesar en la primera ejecución
SENTINELX_FIRST_RUN_BACKFILL_DAYS="3"
```

---

## 4. Ejecución y Prueba Manual

Para forzar una recolección manual de logs inmediata:

```bash
ENV_FILE=/etc/sentinelx-agent.env /usr/local/bin/sentinelx-agent.sh
```

### Verificación de Logs del Agente
Consulte el registro de ejecución en el cliente:

```bash
tail -f /var/log/sentinelx-agent.log
```

---

## 5. Tareas Cron Automatizadas

El instalador configura una tarea cron periódica en `/etc/crontab` para recolectar logs cada 30 minutos:

```cron
*/30 * * * * ENV_FILE=/etc/sentinelx-agent.env /usr/local/bin/sentinelx-agent.sh >> /var/log/sentinelx-agent.log 2>&1
```

---

## 6. Solución de Problemas Frecuentes

1. **Error de Autenticación 401/403**:
   Verifique que la `SENTINELX_API_KEY` en `/etc/sentinelx-agent.env` esté activa en el panel bajo `/dashboard/api-keys`.

2. **Bloqueo por Firewall (cPanel CSF / iptables)**:
   Asegúrese de que el servidor cliente tenga conectividad saliente en el puerto 8000 o 443 hacia el servidor SIEM.

3. **Reinicio de Estado e Historias del Agente**:
   Para limpiar el spool temporal e históricamente recolectado:
   ```bash
   rm -rf /var/spool/sentinelx-agent/* /var/lib/sentinelx-agent/*
   ```
