#!/usr/bin/env bash
set -euo pipefail

AGENT_URL="https://raw.githubusercontent.com/caap1234/SIEM-SentinelXv2.0/main/agent/sentinelx-agent.sh?v=$(date +%s)"
AGENT_BIN="/usr/local/bin/sentinelx-agent.sh"
ENV_FILE="/etc/sentinelx-agent.env"
LOG_FILE="/var/log/sentinelx-agent.log"
CRON_CMD="ENV_FILE=/etc/sentinelx-agent.env /usr/local/bin/sentinelx-agent.sh >> /var/log/sentinelx-agent.log 2>&1"
CRON_EXPR="*/3 * * * *"

echo "============================================================"
echo "    SentinelX SIEM — Instalación del Agente de Log Ingest"
echo "============================================================"

# Función para leer entradas interactivamente (soporta pipe de curl via /dev/tty)
read_prompt() {
  local prompt_msg="$1"
  local target_var="$2"
  local is_secret="${3:-0}"
  local val=""

  if [[ -c /dev/tty ]]; then
    if [[ "$is_secret" == "1" ]]; then
      read -rsp "$prompt_msg" val </dev/tty
      echo >&2
    else
      read -rp "$prompt_msg" val </dev/tty
    fi
  elif [[ -t 0 ]]; then
    if [[ "$is_secret" == "1" ]]; then
      read -rsp "$prompt_msg" val
      echo >&2
    else
      read -rp "$prompt_msg" val
    fi
  fi

  eval "$target_var=\"$val\""
}

# -------------------------------------------------------------------
# 1) Desinstalar y limpiar versión previa
# -------------------------------------------------------------------
echo "[1/9] Eliminando cron y tareas previas..."
TMP_CRON="$(mktemp)"
crontab -l 2>/dev/null | grep -v "sentinelx-agent.sh" > "$TMP_CRON" || true
crontab "$TMP_CRON"
rm -f "$TMP_CRON"

echo "[2/9] Deteniendo procesos activos del agente..."
pkill -f sentinelx-agent.sh 2>/dev/null || true

# -------------------------------------------------------------------
# 3) Descargar nuevo binario del agente
# -------------------------------------------------------------------
echo "[3/9] Descargando la versión más reciente del agente..."
TMP_AGENT="$(mktemp)"
curl -fsSL "$AGENT_URL" -o "$TMP_AGENT"

echo "[4/9] Instalando binario en $AGENT_BIN ..."
rm -f "$AGENT_BIN"
mv "$TMP_AGENT" "$AGENT_BIN"
chmod 0750 "$AGENT_BIN"
chown root:root "$AGENT_BIN"

# -------------------------------------------------------------------
# 5) Limpieza profunda de cola, estados y logs de ejecución
# -------------------------------------------------------------------
echo "[5/9] Limpiando archivos temporales, spool y logs viejos..."
rm -rf \
  /var/spool/sentinelx-agent/* \
  /var/lib/sentinelx-agent/* \
  /tmp/sentinelx-agent/* \
  /var/lock/sentinelx-agent.lock* 2>/dev/null || true

# Vaciar log anterior
: > "$LOG_FILE" 2>/dev/null || rm -f "$LOG_FILE"

# Asegurar directorios base
mkdir -p /var/spool/sentinelx-agent /var/lib/sentinelx-agent /tmp/sentinelx-agent
chmod 0750 /var/spool/sentinelx-agent /var/lib/sentinelx-agent /tmp/sentinelx-agent

# -------------------------------------------------------------------
# 6) Configuración Interactiva
# -------------------------------------------------------------------
echo
echo "------------------------------------------------------------"
echo "                CONFIGURACIÓN DEL AGENTE"
echo "------------------------------------------------------------"

# Pedir API Key
SENTINELX_API_KEY=""
while [[ -z "$SENTINELX_API_KEY" ]]; do
  read_prompt "Ingresa la SENTINELX_API_KEY del servidor: " SENTINELX_API_KEY 0
  if [[ -z "$SENTINELX_API_KEY" ]]; then
    echo "  [!] La API Key no puede estar vacía. Inténtalo de nuevo."
  fi
done

# Seleccionar tipo de servidor/panel
echo
echo "Selecciona la modalidad de tu Servidor / Panel de Control:"
echo "  1) cPanel & WHM (cpanel)"
echo "  2) DirectAdmin (directadmin)"
echo "  3) Detección Automática (auto)"
echo "  4) Linux Genérico / Nginx / Apache (generic)"
read_prompt "Opción [1-4, por defecto 3]: " MODE_OPT 0

case "${MODE_OPT:-3}" in
  1) SENTINELX_MODE="cpanel" ;;
  2) SENTINELX_MODE="directadmin" ;;
  4) SENTINELX_MODE="generic" ;;
  *) SENTINELX_MODE="auto" ;;
esac

# Pedir URL del Backend SIEM
DEFAULT_URL="https://api.sentinelx.tokyo-03.com/logs/ingest"
read_prompt "URL del Ingest del SIEM [por defecto ${DEFAULT_URL}]: " INPUT_URL 0
SENTINELX_INGEST_URL="${INPUT_URL:-$DEFAULT_URL}"

# -------------------------------------------------------------------
# 7) Generar archivo /etc/sentinelx-agent.env
# -------------------------------------------------------------------
echo "[7/9] Generando $ENV_FILE ..."
rm -f "$ENV_FILE"
cat > "$ENV_FILE" <<EOF
# /etc/sentinelx-agent.env — Configuración de Agente SentinelX SIEM
SENTINELX_INGEST_URL="${SENTINELX_INGEST_URL}"
SENTINELX_API_KEY="${SENTINELX_API_KEY}"
SENTINELX_MODE="${SENTINELX_MODE}"

# Ingesta inicial y buffers
SENTINELX_FIRST_RUN_BACKFILL_DAYS="3"
SENTINELX_FIRST_RUN_CONTEXT_LINES="200"
SENTINELX_FIRST_RUN_BACKFILL_MB="50"
SENTINELX_FIRST_RUN_SCAN_MB="64"
SENTINELX_CHUNK_MB="50"

# Bootstrap inteligente por antigüedad (logs de dominio nginx)
# Contexto mínimo garantizado — ningún archivo es ignorado (A3)
SENTINELX_NGINX_DOMAIN_LINES_ACTIVE="50"    # archivos modificados <24h
SENTINELX_NGINX_DOMAIN_LINES_RECENT="20"    # archivos modificados 1-7 días
SENTINELX_NGINX_DOMAIN_LINES_INACTIVE="10"  # archivos sin cambio >7 días (mínimo)

# Caché TTL del glob de dominios nginx (segundos)
SENTINELX_DOMAIN_CACHE_TTL="300"

# Timeouts y límites
SENTINELX_CONNECT_TIMEOUT="10"
SENTINELX_MAX_TIME="7200"
SENTINELX_MAX_SECONDS_PER_RUN="3300"
SENTINELX_SLEEP_BETWEEN_SENDS="0"
SENTINELX_SAR_BACKFILL_DAYS="3"

# Detección de binarios y recuperación segura de spool
SENTINELX_PYTHON_BIN="python3"
SENTINELX_RESET_ON_BACKEND_DOWN="0"
SENTINELX_RESET_ON_SEND_FAILURE="0"
EOF

chmod 0600 "$ENV_FILE"
chown root:root "$ENV_FILE"

# -------------------------------------------------------------------
# 8) Reinstalar Cron automático
# -------------------------------------------------------------------
echo "[8/9] Instalando programador Cron (${CRON_EXPR})..."
(
  crontab -l 2>/dev/null
  echo "${CRON_EXPR} ${CRON_CMD}"
) | crontab -

# -------------------------------------------------------------------
# 9) Resumen Final
# -------------------------------------------------------------------
echo
echo "============================================================"
echo "      INSTALACIÓN DEL AGENTE SENTINELX COMPLETADA CON ÉXITO "
echo "============================================================"
echo " Configuración Instalada:"
echo "   - Agente Binario: $AGENT_BIN"
echo "   - Archivo Env:    $ENV_FILE"
echo "   - Modo Panel:     $SENTINELX_MODE"
echo "   - Endpoint SIEM:  $SENTINELX_INGEST_URL"
echo "   - Cron Programado: ${CRON_EXPR}"
echo "------------------------------------------------------------"
echo " Para ejecutar una prueba manual inmediata:"
echo "   ENV_FILE=/etc/sentinelx-agent.env /usr/local/bin/sentinelx-agent.sh"
echo "============================================================"
