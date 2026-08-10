#!/usr/bin/env bash
# ============================================================
# SentinelX SIEM — Script de Instalación y Despliegue de Producción
# - Instalación idempotente para VPS Limpio o VPS con cPanel/WHM.
# - Detección de Python (>= 3.9 requerida; auto-instala Python 3.11 si la distro trae 3.6).
# - Detección automática de SO (AlmaLinux, Rocky, CentOS, RHEL, Ubuntu, Debian).
# - Cálculo automático de Workers (Parsing & Engine) según CPU/RAM del servidor.
# - Configuración interactiva de Dominio de API Backend & Reverse Proxy (Nginx).
# - Despliegue del Frontend compilado en la ruta web personalizada (ej: /home/sentinelx/public_html)
#   con permisos 755/644 y propietario correcto (sentinelx).
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

install_packages() {
  local os_id; os_id="$(detect_os)"
  log_info "Instalando paquetes requeridos en ${os_id}..."
  if [[ "$os_id" =~ (almalinux|rocky|rhel|centos|fedora) ]]; then
    dnf -y install "$@" 2>/dev/null || yum -y install "$@"
  elif [[ "$os_id" =~ (debian|ubuntu) ]]; then
    apt-get update -y
    apt-get install -y "$@"
  else
    log_error "Sistema operativo no soportado automáticamente (ID=${os_id}). Instale manualmente: $*"
  fi
}

# ---------- Búsqueda e Instalación de Python 3.9+ ----------
find_suitable_python() {
  for py_bin in python3.12 python3.11 python3.10 python3.9 python3; do
    if has_cmd "$py_bin"; then
      local ver
      ver="$("$py_bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")"
      local major="${ver%%.*}"
      local minor="${ver#*.}"
      if [[ "$major" -eq 3 && "$minor" -ge 9 ]]; then
        echo "$py_bin"
        return 0
      fi
    fi
  done
  echo ""
}

ensure_modern_python() {
  local selected_py
  selected_py="$(find_suitable_python)"

  if [[ -z "$selected_py" ]]; then
    log_warn "Se detectó una versión de Python antigua (< 3.9). SentinelX requiere Python 3.9 o superior."
    if is_root; then
      log_info "Instalando Python 3.11 en el sistema..."
      local os_id; os_id="$(detect_os)"
      if [[ "$os_id" =~ (almalinux|rocky|rhel|centos|fedora) ]]; then
        install_packages python311 python311-pip python311-devel 2>/dev/null || install_packages python39 python39-pip
      elif [[ "$os_id" =~ (debian|ubuntu) ]]; then
        install_packages python3 python3-pip python3-venv
      fi
      selected_py="$(find_suitable_python)"
    fi
  fi

  if [[ -z "$selected_py" ]]; then
    log_error "No se encontró un ejecutable de Python >= 3.9. Por favor instale Python 3.9, 3.10 o 3.11 en su servidor."
  fi

  echo "$selected_py"
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

gen_secret_key() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
}

gen_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits + "_-!"
print("".join(secrets.choice(alphabet) for _ in range(24)))
PY
}

ensure_docker_compose_file() {
  if [[ -f "${COMPOSE_EXAMPLE_FILE}" ]]; then
    log_info "Sincronizando ${COMPOSE_FILE} con la plantilla de producción (${COMPOSE_EXAMPLE_FILE})..."
    cp -f "${COMPOSE_EXAMPLE_FILE}" "${COMPOSE_FILE}"
  elif [[ -f "${ROOT_DIR}/docker-compose.local.yml" ]]; then
    log_info "Sincronizando ${COMPOSE_FILE} desde docker-compose.local.yml..."
    cp -f "${ROOT_DIR}/docker-compose.local.yml" "${COMPOSE_FILE}"
  fi
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
    log_info "CSF Firewall detectado. Asegurando compatibilidad con Docker y apertura de puertos..."
    local conf="/etc/csf/csf.conf"
    if [[ -f "$conf" ]]; then
      # 1. Habilitar integración con Docker
      if ! grep -qE '^DOCKER\s*=\s*"1"' "$conf"; then
        if confirm "¿Desea habilitar DOCKER=\"1\" en CSF para evitar bloqueo de puertos/redes? (Recomendado)" "y"; then
          sed -i 's/^DOCKER\s*=.*/DOCKER = "1"/' "$conf" || echo 'DOCKER = "1"' >> "$conf"
          csf -r >/dev/null 2>&1 || true
          log_info "CSF actualizado con DOCKER=\"1\"."
        fi
      fi

      # 2. Verificar e incluir puertos de SentinelX en TCP_IN (8000, 4222, 9000)
      local ports_needed=(8000 4222 9000)
      local missing_ports=()
      for p in "${ports_needed[@]}"; do
        if ! grep -E '^TCP_IN\s*=' "$conf" | grep -qE "\b${p}\b"; then
          missing_ports+=("$p")
        fi
      done

      if [[ "${#missing_ports[@]}" -gt 0 ]]; then
        log_info "Añadiendo puertos de SentinelX (${missing_ports[*]}) a TCP_IN en /etc/csf/csf.conf..."
        if is_root; then
          sed -i -E 's/^(TCP_IN\s*=\s*"[^"]*)/\1,8000,4222,9000/' "$conf" 2>/dev/null || true
          csf -r >/dev/null 2>&1 || true
          log_info "Puertos 8000 (API), 4222 (NATS) y 9000 (MinIO) añadidos a CSF y firewall reiniciado."
        fi
      fi
    fi
  fi
}

# ---------- Preparación de Entorno Python y Dependencias ----------
setup_python_venv() {
  log_info "Verificando ejecutable de Python moderno (Python >= 3.9)..."
  local py_cmd
  py_cmd="$(ensure_modern_python)"

  local py_ver
  py_ver="$("$py_cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")"
  log_info "Usando ejecutable de Python: ${py_cmd} (Versión ${py_ver})"

  # Si el entorno virtual (.venv) existía con Python antiguo (< 3.9), eliminarlo
  if [[ -d "${ROOT_DIR}/.venv" ]]; then
    local venv_ver
    venv_ver="$("${ROOT_DIR}/.venv/bin/python" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3.6")"
    local v_minor="${venv_ver#*.}"
    if [[ "${venv_ver%%.*}" -ne 3 || "$v_minor" -lt 9 ]]; then
      log_warn "El entorno virtual existente (.venv) usaba Python ${venv_ver} (obsoleto). Recreando con ${py_cmd} (${py_ver})..."
      rm -rf "${ROOT_DIR}/.venv"
    fi
  fi

  if [[ ! -d "${ROOT_DIR}/.venv" ]]; then
    log_info "Creando entorno virtual Python (.venv) con ${py_cmd}..."
    "$py_cmd" -m venv "${ROOT_DIR}/.venv"
  fi

  log_info "Actualizando pip, setuptools y wheel..."
  "${ROOT_DIR}/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  if [[ -f "${ROOT_DIR}/requirements.txt" ]]; then
    log_info "Instalando dependencias de Python desde requirements.txt..."
    "${ROOT_DIR}/.venv/bin/pip" install -r "${ROOT_DIR}/requirements.txt"
  fi
}

# ---------- Generación de Reverse Proxy Nginx para la API ----------
generate_nginx_api_reverse_proxy() {
  local api_url="$1"
  local host_name
  host_name="$(echo "$api_url" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/.*||' -e 's|:.*||')"

  if [[ -z "${host_name}" || "${host_name}" == "localhost" || "${host_name}" == "127.0.0.1" ]]; then
    return 0
  fi

  log_info "Generando configuración Nginx Reverse Proxy para el dominio de API: ${host_name}..."
  mkdir -p "${ROOT_DIR}/config"
  cat > "${ROOT_DIR}/config/sentinelx-api.conf" <<EOF
# SentinelX SIEM API - Configuración de Reverse Proxy Nginx
server {
    listen 80;
    server_name ${host_name};

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        proxy_send_timeout 300s;
    }
}
EOF

  log_info "Plantilla de Nginx creada en: ${ROOT_DIR}/config/sentinelx-api.conf"

  if is_root && [[ -d /etc/nginx/conf.d ]]; then
    cp -f "${ROOT_DIR}/config/sentinelx-api.conf" /etc/nginx/conf.d/sentinelx-api.conf 2>/dev/null || true
    if has_cmd nginx; then
      nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
      log_info "Reverse Proxy Nginx activado en /etc/nginx/conf.d/sentinelx-api.conf"
    fi
  fi
}

# ---------- Compilación de Frontend Astro & Asignación de Permisos ----------
setup_frontend() {
  local deploy_target="${1:-}"
  local api_url="${2:-http://localhost:8000}"

  if [[ -d "${FRONT_SRC_DEFAULT}" && -f "${FRONT_SRC_DEFAULT}/package.json" ]]; then
    log_info "Configurando y construyendo el frontend web Astro (PUBLIC_API_URL=${api_url})..."
    if ! has_cmd node || ! has_cmd npm; then
      if is_root; then
        install_packages nodejs npm
      else
        log_error "Falta Node.js/npm para compilar el frontend. Instálelo o ejecute como root."
      fi
    fi

    # Inyectar PUBLIC_API_URL en el build de Astro
    (cd "${FRONT_SRC_DEFAULT}" && npm install >/dev/null && PUBLIC_API_URL="${api_url}" npm run build >/dev/null)
    log_info "Frontend compilado exitosamente en front/dist."

    if [[ -n "${deploy_target}" ]]; then
      log_info "Copiando Frontend estático a la ruta web: ${deploy_target}..."
      mkdir -p "${deploy_target}"
      cp -rf "${FRONT_SRC_DEFAULT}/dist/"* "${deploy_target}/"

      # Determinar usuario y grupo propietario (ej: sentinelx)
      local owner_user="sentinelx"
      local owner_group="sentinelx"

      if [[ -d "/home/sentinelx" ]]; then
        owner_user="$(stat -c '%U' /home/sentinelx 2>/dev/null || echo sentinelx)"
        owner_group="$(stat -c '%G' /home/sentinelx 2>/dev/null || echo sentinelx)"
      elif [[ -d "${deploy_target}" ]]; then
        owner_user="$(stat -c '%U' "${deploy_target}" 2>/dev/null || echo sentinelx)"
        owner_group="$(stat -c '%G' "${deploy_target}" 2>/dev/null || echo sentinelx)"
      fi

      if is_root && id -u "${owner_user}" >/dev/null 2>&1; then
        log_info "Asignando propietario (${owner_user}:${owner_group}) a ${deploy_target}..."
        chown -R "${owner_user}:${owner_group}" "${deploy_target}" 2>/dev/null || true
      fi

      log_info "Estableciendo permisos 755 (directorios) y 644 (archivos) en ${deploy_target}..."
      find "${deploy_target}" -type d -exec chmod 755 {} + 2>/dev/null || true
      find "${deploy_target}" -type f -exec chmod 644 {} + 2>/dev/null || true
      log_info "Frontend desplegado con permisos correctos en: ${deploy_target}"
    fi
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
echo "1) Instalación Limpia Producción (Systemd local + Nginx web)"
echo "2) Instalación Híbrida / Docker (Backend & Microservicios en Docker + Front en ruta Web)"
echo "3) Instalación Rápida de Prueba (FAST / Localhost)"
prompt DEPLOY_MODE "Elija opción (1/2/3)" "2" 0 0

# Configurar réplicas de workers
PARSING_WORKERS="${REC_PARSING}"
ENGINE_WORKERS="${REC_ENGINE}"
FRONT_DEPLOY_PATH=""
PUBLIC_API_URL="https://api.sentinelx.tokyo-03.com"

INITIAL_ADMIN_EMAIL="admin@sentinelx.local"
INITIAL_ADMIN_PASSWORD=""
INITIAL_ADMIN_FULL_NAME="SentinelX Admin"

if [[ "${DEPLOY_MODE}" != "3" ]]; then
  echo
  echo "Configuración del Administrador Inicial del SIEM:"
  prompt INITIAL_ADMIN_EMAIL "Correo electrónico del Administrador Inicial" "admin@sentinelx.local" 0 0
  prompt INITIAL_ADMIN_PASSWORD "Contraseña del Administrador Inicial (vacío para autogenerar)" "" 1 1
  if [[ -z "${INITIAL_ADMIN_PASSWORD}" ]]; then
    INITIAL_ADMIN_PASSWORD="$(gen_password)"
    log_info "Contraseña de Administrador autogenerada."
  fi
  prompt INITIAL_ADMIN_FULL_NAME "Nombre del Administrador" "SentinelX Admin" 0 0

  echo
  echo "Configuración de Dominio & API Backend:"
  prompt PUBLIC_API_URL "URL pública o dominio de la API Backend (ej: https://api.sentinelx.tokyo-03.com)" "${PUBLIC_API_URL}" 0 0

  if [[ -n "${PUBLIC_API_URL}" && ! "${PUBLIC_API_URL}" =~ ^https?:// ]]; then
    PUBLIC_API_URL="https://${PUBLIC_API_URL}"
  fi
  PUBLIC_API_URL="${PUBLIC_API_URL%/}"

  echo
  echo "Configuración del Frontend Web:"
  DEFAULT_PUBLIC_HTML="/home/sentinelx/public_html"
  [[ -d "/home/sentinelx/public_html" ]] || DEFAULT_PUBLIC_HTML="/var/www/html"
  prompt FRONT_DEPLOY_PATH "Ruta donde deseas copiar los archivos del Frontend web estático" "${DEFAULT_PUBLIC_HTML}" 0 0

  echo
  echo "Configuración de Workers de Procesamiento:"
  echo "  (Basado en tus ${HW_CPUS} Cores / ${HW_RAM_MB} MB RAM)"
  prompt PARSING_WORKERS "Número de Parsing Workers (Normalización & GeoIP)" "${REC_PARSING}" 0 0
  prompt ENGINE_WORKERS "Número de Engine Workers (Motor de Correlación v2)" "${REC_ENGINE}" 0 0
fi

# Generar Reverse Proxy si aplica
generate_nginx_api_reverse_proxy "${PUBLIC_API_URL}"

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
  [[ -n "${INITIAL_ADMIN_EMAIL:-}" ]] || INITIAL_ADMIN_EMAIL="admin@sentinelx.local"
  [[ -n "${INITIAL_ADMIN_PASSWORD:-}" ]] || INITIAL_ADMIN_PASSWORD="$(gen_password)"
  [[ -n "${INITIAL_ADMIN_FULL_NAME:-}" ]] || INITIAL_ADMIN_FULL_NAME="SentinelX Admin"

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
PUBLIC_API_URL=${PUBLIC_API_URL}
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
setup_frontend "${FRONT_DEPLOY_PATH}" "${PUBLIC_API_URL}"

# ============================================================
# DESPLIEGUE SEGÚN MODO
# ============================================================
if [[ "${DEPLOY_MODE}" == "1" ]]; then
  install_systemd_services
  log_info "Ejecutando script de configuración inicial (FIRST_INSTALL)..."
  "${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/scripts/initial_setup.py" || true
  log_info "Instalación por Servicios Systemd completada con ${PARSING_WORKERS} Parsing Workers y ${ENGINE_WORKERS} Engine Workers."
elif [[ "${DEPLOY_MODE}" == "2" ]]; then
  if has_cmd docker && docker compose version >/dev/null 2>&1; then
    ensure_docker_compose_file
    log_info "Levantando stack Docker Compose (Escala calculada: parsing_worker=${PARSING_WORKERS}, engine_worker=${ENGINE_WORKERS})...."
    if ! docker compose -f "${COMPOSE_FILE}" up -d --build \
      --scale "parsing_worker=${PARSING_WORKERS}" \
      --scale "engine_worker=${ENGINE_WORKERS}"; then
      log_warn "Aviso en la red/iptables de Docker. Reiniciando servicio de Docker (systemctl restart docker)..."
      if is_root && has_cmd systemctl; then
        systemctl restart docker
        sleep 3
        log_info "Reintentando levantar el stack Docker Compose..."
        docker compose -f "${COMPOSE_FILE}" up -d --build \
          --scale "parsing_worker=${PARSING_WORKERS}" \
          --scale "engine_worker=${ENGINE_WORKERS}"
      fi
    fi
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
echo " Dominio & Rutas:"
echo "   - API Domain:      ${PUBLIC_API_URL}"
if [[ -n "${FRONT_DEPLOY_PATH}" ]]; then
  echo "   - Frontend Ruta:   ${FRONT_DEPLOY_PATH}"
fi
echo "------------------------------------------------------------"
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
echo "   - API Backend:  ${PUBLIC_API_URL} -> http://localhost:8000"
echo "   - Log de Inst.: ${INSTALL_LOG}"
echo "============================================================"
