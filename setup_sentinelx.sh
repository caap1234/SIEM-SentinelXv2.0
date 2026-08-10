#!/usr/bin/env bash
# ============================================================
# SentinelX SIEM — Script de Instalación y Despliegue de Producción
# - Instalación idempotente para VPS Limpio o VPS con cPanel/WHM.
# - Detección automática de SO (AlmaLinux, Rocky, CentOS, RHEL, Ubuntu, Debian).
# - Cálculo automático de Workers (Parsing & Engine) según CPU/RAM del servidor.
# - Soporte para despliegue por Servicios Systemd o por Docker Compose.
# - Aislamiento en /opt/sentinelx y logs en /var/log/sentinelx/install.log.
# ============================================================

set -euo pipefail

# ---------- Variables de Rutas ----------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/sentinelx"
INSTALL_LOG="${LOG_DIR}/install.log"
TARGET_DIR="/opt/sentinelx"
SYSTEMD_DIR="/etc/systemd/system"

ENV_FILE="${ROOT_DIR}/.env"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
COMPOSE_EXAMPLE_FILE="${ROOT_DIR}/docker-compose.example.yml"

GEOIP_DIR="${ROOT_DIR}/geoip"
COUNTRY_MMDB="${GEOIP_DIR}/GeoLite2-Country.mmdb"
ASN_MMDB="${GEOIP_DIR}/GeoLite2-ASN.mmdb"
FRONT_SRC_DEFAULT="${ROOT_DIR}/front"

# ---------- Preparación de Logging ----------
mkdir -p "${LOG_DIR}" 2>/dev/null || LOG_DIR="/tmp/sentinelx_log"
mkdir -p "${LOG_DIR}"
INSTALL_LOG="${LOG_DIR}/install.log"

exec > >(tee -a "${INSTALL_LOG}") 2>&1

# ---------- Helpers ----------
log_info() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] -> $*"; }
log_warn() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2; }
log_error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; exit 1; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }
require_cmd() { has_cmd "$1" || log_error "Falta comando requerido: $1"; }
is_root() { [[ "${EUID}" -eq 0 ]]; }
is_linux() { [[ "$(uname -s 2>/dev/null || echo unknown)" == "Linux" ]]; }

confirm() {
  local label="$1" default="${2:-y}" ans=""
  read -r -p "${label} [${default}]: " ans
  [[ -z "$ans" ]] && ans="$default"
  [[ "$ans" =~ ^[Yy]$ ]]
}

prompt() {
  local var_name="$1" label="$2" default="${3:-}" secret="${4:-0}" allow_empty="${5:-0}" value=""
  while true; do
    if [[ "$secret" == "1" ]]; then
      if [[ -n "$default" ]]; then
        read -r -s -p "${label} [default oculto]: " value; echo
        [[ -z "$value" ]] && value="$default"
      else
        read -r -s -p "${label}: " value; echo
      fi
    else
      if [[ -n "$default" ]]; then
        read -r -p "${label} [${default}]: " value
        [[ -z "$value" ]] && value="$default"
      else
        read -r -p "${label}: " value
      fi
    fi
    if [[ "$allow_empty" == "1" ]]; then break; fi
    [[ -n "$value" ]] && break
    echo "-> Este valor no puede ir vacío."
  done
  printf -v "$var_name" "%s" "$value"
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

# ---------- Cálculo Automático de Recursos de Hardware ----------
calculate_recommended_workers() {
  local cpus ram_mb
  if has_cmd nproc; then
    cpus="$(nproc)"
  else
    cpus="$(python3 -c "import os; print(os.cpu_count() or 2)" 2>/dev/null || echo 2)"
  fi

  if [[ -f /proc/meminfo ]]; then
    ram_mb="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)"
  else
    ram_mb=4096
  fi

  local rec_parsing=1
  local rec_engine=1

  if [[ "$cpus" -ge 8 ]]; then
    rec_parsing=4
    rec_engine=2
  elif [[ "$cpus" -ge 4 ]]; then
    rec_parsing=2
    rec_engine=2
  elif [[ "$cpus" -ge 2 ]]; then
    rec_parsing=1
    rec_engine=1
  fi

  echo "${cpus}:${ram_mb}:${rec_parsing}:${rec_engine}"
}

install_packages() {
  local os_id; os_id="$(detect_os)"
  log_info "Instalando paquetes requeridos en ${os_id}..."
  if [[ "$os_id" =~ (almalinux|rocky|rhel|centos|fedora) ]]; then
    dnf -y install "$@"
  elif [[ "$os_id" =~ (debian|ubuntu) ]]; then
    apt-get update -y
    apt-get install -y "$@"
  else
    log_error "Sistema operativo no soportado automáticamente (ID=${os_id}). Instale manualmente: $*"
  fi
}

gen_secret_key() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
}

gen_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits + "!@#$%_=+-."
print("".join(secrets.choice(alphabet) for _ in range(24)))
PY
}

urlencode_str() {
  python3 - <<'PY'
import os, urllib.parse
s = os.environ.get("SX_URLENCODE_IN", "")
print(urllib.parse.quote(s, safe=""))
PY
}

# ---------- Verificación de Puertos y cPanel ----------
check_cpanel_and_ports() {
  log_info "Verificando presencia de cPanel/WHM y disponibilidad de puertos..."
  if [[ -d /usr/local/cpanel ]]; then
    log_warn "cPanel/WHM detectado en el servidor."
    log_warn "SentinelX SIEM se desplegará en puertos dedicados sin interferir con cPanel."
  fi

  local reserved_ports=(8000 4321 5432 9200 9000 9001 4222)
  for port in "${reserved_ports[@]}"; do
    if has_cmd netstat && netstat -tuln | grep -q ":${port} "; then
      log_warn "El puerto ${port} está en uso por otro servicio."
    fi
  done
}

# ---------- Verificación CSF Firewall ----------
check_csf_firewall() {
  if is_linux && [[ -x /usr/sbin/csf || -x /usr/local/sbin/csf ]]; then
    log_info "CSF Firewall detectado. Asegurando compatibilidad con Docker/Systemd..."
    local conf="/etc/csf/csf.conf"
    if [[ -f "$conf" ]]; then
      if ! grep -qE '^DOCKER\s*=\s*"1"' "$conf"; then
        if confirm "¿Desea habilitar DOCKER=\"1\" en CSF para evitar bloqueo de puertos? (Recomendado)" "y"; then
          sed -i 's/^DOCKER\s*=.*/DOCKER = "1"/' "$conf" || echo 'DOCKER = "1"' >> "$conf"
          csf -r >/dev/null 2>&1 || true
          log_info "CSF actualizado y reiniciado."
        fi
      fi
    fi
  fi
}

# ---------- Preparación de Entorno Python y Dependencias ----------
setup_python_venv() {
  log_info "Configurando entorno virtual de Python (.venv)..."
  require_cmd python3

  if ! python3 -c "import venv" >/dev/null 2>&1; then
    if is_root; then
      install_packages python3-venv python3-pip
    else
      log_error "Falta el módulo python3-venv. Instálelo o ejecute como root."
    fi
  fi

  if [[ ! -d "${ROOT_DIR}/.venv" ]]; then
    python3 -m venv "${ROOT_DIR}/.venv"
  fi

  "${ROOT_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  if [[ -f "${ROOT_DIR}/requirements.txt" ]]; then
    log_info "Instalando dependencias de Python desde requirements.txt..."
    "${ROOT_DIR}/.venv/bin/pip" install -r "${ROOT_DIR}/requirements.txt" >/dev/null
  fi
}

# ---------- Compilación de Frontend Astro ----------
setup_frontend() {
  if [[ -d "${FRONT_SRC_DEFAULT}" && -f "${FRONT_SRC_DEFAULT}/package.json" ]]; then
    log_info "Configurando y construyendo el frontend web Astro..."
    if ! has_cmd node || ! has_cmd npm; then
      if is_root; then
        install_packages nodejs npm
      else
        log_error "Falta Node.js/npm para compilar el frontend. Instálelo o ejecute como root."
      fi
    fi
    (cd "${FRONT_SRC_DEFAULT}" && npm install >/dev/null && npm run build >/dev/null)
    log_info "Frontend compilado exitosamente en front/dist."
  fi
}

# ---------- Instalación de Servicios Systemd ----------
install_systemd_services() {
  if ! is_root; then
    log_warn "Se requieren permisos de root para instalar los servicios systemd en /etc/systemd/system/."
    return 0
  fi

  log_info "Instalando servicios systemd de SentinelX SIEM..."

  # Crear usuario de sistema dedicado 'sentinelx'
  if ! id -u sentinelx >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /opt/sentinelx sentinelx || true
    log_info "Usuario de sistema 'sentinelx' creado."
  fi

  # Copiar archivos .service si existen en scripts/systemd/
  local sysd_src="${ROOT_DIR}/scripts/systemd"
  if [[ -d "${sysd_src}" ]]; then
    cp -f "${sysd_src}"/sentinelx-*.service /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    log_info "Unidades de servicio systemd recargadas."
  fi
}

# ============================================================
# CABECERA DE INICIO
# ============================================================
echo "============================================================"
echo "         SentinelX SIEM — Instalador de Producción          "
echo "============================================================"
log_info "Directorio de proyecto: ${ROOT_DIR}"
log_info "Archivo de log: ${INSTALL_LOG}"

check_cpanel_and_ports
check_csf_firewall

# Detectar hardware y calcular recomendación de workers
HW_INFO="$(calculate_recommended_workers)"
IFS=":" read -r HW_CPUS HW_RAM_MB REC_PARSING REC_ENGINE <<< "${HW_INFO}"

log_info "Recursos de Hardware detectados: ${HW_CPUS} CPU Cores | ~${HW_RAM_MB} MB RAM"
log_info "Recomendación calculada automáticamente: ${REC_PARSING} Parsing Workers, ${REC_ENGINE} Engine Workers"

# ============================================================
# MODO DE INSTALACIÓN
# ============================================================
echo
echo "Seleccione el Modo de Instalación:"
echo "1) Instalación Limpia Producción (Systemd + PostgreSQL + Node + Python local)"
echo "2) Instalación Docker Compose (Contenedores aislados)"
echo "3) Instalación Rápida de Prueba (FAST / Localhost)"
prompt DEPLOY_MODE "Elija opción (1/2/3)" "1" 0 0

# Configurar réplicas de workers
PARSING_WORKERS="${REC_PARSING}"
ENGINE_WORKERS="${REC_ENGINE}"

if [[ "${DEPLOY_MODE}" != "3" ]]; then
  echo
  echo "Configuración de Workers de Procesamiento:"
  echo "  (Basado en tus ${HW_CPUS} Cores / ${HW_RAM_MB} MB RAM)"
  prompt PARSING_WORKERS "Número de Parsing Workers (Normalización & GeoIP)" "${REC_PARSING}" 0 0
  prompt ENGINE_WORKERS "Número de Engine Workers (Motor de Correlación v2)" "${REC_ENGINE}" 0 0
fi

# ============================================================
# CREACIÓN DE ARCHIVO .ENV
# ============================================================
if [[ ! -f "${ENV_FILE}" || "${DEPLOY_MODE}" == "3" ]]; then
  log_info "Generando archivo de entorno de producción .env..."

  POSTGRES_DB="sentinelx_db"
  POSTGRES_USER="sentinelx"
  POSTGRES_PASSWORD="$(gen_password)"
  export SX_URLENCODE_IN="${POSTGRES_PASSWORD}"
  DB_PASS_URLENC="$(urlencode_str)"
  unset SX_URLENCODE_IN
  DATABASE_URL="postgresql://${POSTGRES_USER}:${DB_PASS_URLENC}@localhost:5432/${POSTGRES_DB}"

  SECRET_KEY="$(gen_secret_key)"
  INITIAL_ADMIN_EMAIL="admin@sentinelx.local"
  INITIAL_ADMIN_PASSWORD="$(gen_password)"
  INITIAL_ADMIN_FULL_NAME="SentinelX Admin"

  cat > "${ENV_FILE}" <<EOF
# SentinelX SIEM - Configuración de Entorno Generada Automáticamente
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_PORT=5432
DATABASE_URL=${DATABASE_URL}

SECRET_KEY=${SECRET_KEY}
ACCESS_TOKEN_EXPIRE_MINUTES=480
BACKEND_PORT=8000

INITIAL_ADMIN_EMAIL=${INITIAL_ADMIN_EMAIL}
INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}
INITIAL_ADMIN_FULL_NAME=${INITIAL_ADMIN_FULL_NAME}

OPENSEARCH_URL=http://localhost:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=admin

NATS_URL=nats://localhost:4222
NATS_PORT=4222
NATS_MGMT_PORT=8222

MINIO_ENDPOINT=http://localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET_NAME=sentinelx-evidence

UPLOADED_LOGS_DIR=/opt/sentinelx/uploaded_logs
GEOIP_COUNTRY_DB_PATH=/opt/sentinelx/geoip/GeoLite2-Country.mmdb
GEOIP_ASN_DB_PATH=/opt/sentinelx/geoip/GeoLite2-ASN.mmdb

ENRICH_INLINE=1
ENRICH_CACHE_TTL=86400
ENRICH_CACHE_MAX=100000
RULES_RELOAD_SECONDS=60

PARSING_WORKERS=${PARSING_WORKERS}
ENGINE_WORKERS=${ENGINE_WORKERS}

FRONTEND_BASE_URL=http://localhost:4321/
PUBLIC_API_URL=http://localhost:8000
EOF

  chmod 600 "${ENV_FILE}"
  log_info "Archivo .env creado y protegido (chmod 600)."
else
  log_info "Archivo .env detectado. (Se preservará la configuración existente)."
fi

# ============================================================
# INSTALACIÓN DE DEPENDENCIAS Y ENTORNOS
# ============================================================
setup_python_venv
setup_frontend

# ============================================================
# PRIMERA INSTALACIÓN Y CONFIGURACIÓN INICIAL (FIRST_INSTALL)
# ============================================================
log_info "Ejecutando script de configuración inicial (FIRST_INSTALL)..."
"${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/scripts/initial_setup.py" || log_warn "Aviso en inicialización inicial. Asegúrese de que los servicios PostgreSQL/OpenSearch estén arriba."

# ============================================================
# DESPLIEGUE SEGÚN MODO
# ============================================================
if [[ "${DEPLOY_MODE}" == "1" ]]; then
  install_systemd_services
  log_info "Instalación por Servicios Systemd completada con ${PARSING_WORKERS} Parsing Workers y ${ENGINE_WORKERS} Engine Workers."
elif [[ "${DEPLOY_MODE}" == "2" ]]; then
  if has_cmd docker && docker compose version >/dev/null 2>&1; then
    log_info "Levantando stack Docker Compose (Escala calculada: parsing_worker=${PARSING_WORKERS}, engine_worker=${ENGINE_WORKERS})..."
    docker compose up -d --build \
      --scale "parsing_worker=${PARSING_WORKERS}" \
      --scale "engine_worker=${ENGINE_WORKERS}"
  else
    log_warn "Docker no disponible. Por favor instale Docker para usar la opción 2."
  fi
fi

# ============================================================
# RESUMEN Y CREDENCIALES
# ============================================================
echo
echo "============================================================"
echo "      INSTALACIÓN DE SENTINELX SIEM FINALIZADA CON ÉXITO    "
echo "============================================================"
echo " Recursos & Workers Escala:"
echo "   - CPU / RAM:       ${HW_CPUS} Cores / ~${HW_RAM_MB} MB RAM"
echo "   - Parsing Workers: ${PARSING_WORKERS}"
echo "   - Engine Workers:  ${ENGINE_WORKERS}"
echo "------------------------------------------------------------"
echo " Credenciales del Administrador Inicial:"
echo "   - Email:    ${INITIAL_ADMIN_EMAIL:-admin@sentinelx.local}"
if [[ -n "${INITIAL_ADMIN_PASSWORD:-}" ]]; then
  echo "   - Password: ${INITIAL_ADMIN_PASSWORD}"
fi
echo "============================================================"
echo " Servicios SentinelX:"
echo "   - API Backend:  http://localhost:8000"
echo "   - Frontend Web: http://localhost:4321"
echo "   - Log de Inst.: ${INSTALL_LOG}"
echo "============================================================"
