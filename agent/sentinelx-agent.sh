#/usr/local/bin/sentinelx-agent.sh
#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# SentinelX Agent v2.1 Enterprise - incremental uploader (inode+offset) + spool
# Objetivo: enviar logs por partes, sin perder bytes, sin cortar líneas.
# - NO modifica contenido del log (incluye NUL bytes si existen)
# - Chunks SIEMPRE terminan en '\n' (si existe), evitando líneas partidas
# - Throttling Híbrido: Carga Local (/proc/loadavg) + Backpressure de Backend (Latencia HTTP / 429 / 5xx)
# - Atomicidad Estricta: Persistencia en spool antes de avanzar el offset (.state)
# - Política de Baseline Deliberada para Nginx Domains (15/5/2 líneas)
# ------------------------------------------------------------

ENV_FILE="${ENV_FILE:-/etc/sentinelx-agent.env}"
[[ -f "$ENV_FILE" ]] && # shellcheck disable=SC1090
  source "$ENV_FILE"

: "${SENTINELX_INGEST_URL:?Falta SENTINELX_INGEST_URL}"
: "${SENTINELX_API_KEY:?Falta SENTINELX_API_KEY}"

MODE="${SENTINELX_MODE:-auto}"

# Red / performance
CHUNK_MB="${SENTINELX_CHUNK_MB:-50}"                 # chunk base por iteración
LIMIT_RATE="${SENTINELX_LIMIT_RATE:-}"               # ej: 2m, 500k. Vacío=sin límite
CONNECT_TIMEOUT="${SENTINELX_CONNECT_TIMEOUT:-10}"
MAX_TIME="${SENTINELX_MAX_TIME:-7200}"               # segundos por request
SLEEP_BETWEEN="${SENTINELX_SLEEP_BETWEEN_SENDS:-0}"

# Corte por tiempo de corrida
MAX_SECONDS_PER_RUN="${SENTINELX_MAX_SECONDS_PER_RUN:-3300}" # 55 min

# Primer run (TAIL MODE) & Throttling Parametrizado
FIRST_RUN_CONTEXT_LINES="${SENTINELX_FIRST_RUN_CONTEXT_LINES:-200}"
FIRST_RUN_BACKFILL_MB="${SENTINELX_FIRST_RUN_BACKFILL_MB:-200}"
FIRST_RUN_SCAN_MB="${SENTINELX_FIRST_RUN_SCAN_MB:-256}"
FIRST_RUN_MAX_TOTAL_MB="${SENTINELX_FIRST_RUN_MAX_TOTAL_MB:-15}"

# Throttling local y backpressure backend
THROTTLE_MODERATE_SLEEP="${SENTINELX_THROTTLE_MODERATE_SLEEP:-0.2}"
THROTTLE_HIGH_SLEEP="${SENTINELX_THROTTLE_HIGH_SLEEP:-1.0}"
BACKEND_LATENCY_THRESHOLD_MS="${SENTINELX_BACKEND_LATENCY_THRESHOLD_MS:-1500}"

# Bootstrap inteligente para logs de dominios nginx (por antigüedad del archivo)
# Contexto mínimo garantizado — política deliberada de baseline inicial
NGINX_DOMAIN_LINES_ACTIVE="${SENTINELX_NGINX_DOMAIN_LINES_ACTIVE:-15}"     # modificado <24h
NGINX_DOMAIN_LINES_RECENT="${SENTINELX_NGINX_DOMAIN_LINES_RECENT:-5}"       # modificado 1-7 días
NGINX_DOMAIN_LINES_INACTIVE="${SENTINELX_NGINX_DOMAIN_LINES_INACTIVE:-2}"   # sin cambio >7 días

# Caché del glob de dominios nginx (TTL en segundos)
DOMAIN_CACHE_TTL="${SENTINELX_DOMAIN_CACHE_TTL:-300}" # 5 minutos

# SAR (opcional)
SAR_BACKFILL_DAYS="${SENTINELX_SAR_BACKFILL_DAYS:-3}"  # 0 = deshabilita

STATE_DIR="${STATE_DIR:-/var/lib/sentinelx-agent}"
SPOOL_DIR="${SPOOL_DIR:-/var/spool/sentinelx-agent}"
TMP_DIR="${TMP_DIR:-/tmp/sentinelx-agent}"

LOCK_FILE="${SENTINELX_LOCK_FILE:-/var/lock/sentinelx-agent.lock}"

# Escaneos newline
MAX_NEWLINE_SCAN_BYTES="${SENTINELX_MAX_NEWLINE_SCAN_BYTES:-1048576}"     # busca '\n' hacia atrás dentro de este window
MAX_FORWARD_SCAN_BYTES="${SENTINELX_MAX_FORWARD_SCAN_BYTES:-8388608}"     # busca '\n' hacia adelante (líneas largas) hasta este límite

# Python (recomendado)
PYTHON_BIN="${SENTINELX_PYTHON_BIN:-python3}"

RESET_ON_BACKEND_DOWN="${SENTINELX_RESET_ON_BACKEND_DOWN:-0}"
RESET_ON_SEND_FAILURE="${SENTINELX_RESET_ON_SEND_FAILURE:-0}"

mkdir -p "$STATE_DIR" "$SPOOL_DIR" "$TMP_DIR" "$(dirname "$LOCK_FILE")"
umask 027

RUN_START_EPOCH="$(date -u +%s)"

# Telemetría Global por Corrida
TELEMETRY_START_SEC="$(date +%s)"
TELEMETRY_FILES_SCANNED=0
TELEMETRY_FILES_CHANGED=0
TELEMETRY_FILES_PROCESSED=0
TELEMETRY_JOBS_ENQUEUED=0
TELEMETRY_JOBS_SENT=0
TELEMETRY_JOBS_PENDING=0
TELEMETRY_RAW_BYTES=0
TELEMETRY_COMPRESSED_BYTES=0
TELEMETRY_HTTP_REQUESTS=0
TELEMETRY_HTTP_FAILURES=0
TELEMETRY_LATENCY_SUM_MS=0
TELEMETRY_THROTTLE_MODE="normal"
TELEMETRY_THROTTLE_SLEEPS="0.0"
TELEMETRY_STOP_REASON="completed"
TELEMETRY_LOAD_PEAK="0.00"
TOTAL_FIRST_RUN_ENQUEUED_BYTES=0

log() { echo "[$(date -u +"%Y-%m-%d %H:%M:%S") UTC] $*"; }

time_exceeded() {
  local now
  now="$(date -u +%s)"
  (( now - RUN_START_EPOCH >= MAX_SECONDS_PER_RUN ))
}

need_python() {
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    log "ERROR: se requiere $PYTHON_BIN para garantizar chunks alineados a newline."
    exit 2
  fi
}

get_cpu_cores() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif [[ -f /proc/cpuinfo ]]; then
    grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1
  else
    echo 1
  fi
}

get_load_1min() {
  if [[ -f /proc/loadavg ]]; then
    awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0.00"
  else
    echo "0.00"
  fi
}

get_time_ms() {
  date +%s%3N 2>/dev/null || "$PYTHON_BIN" -c "import time; print(int(time.time()*1000))"
}

check_throttling_and_load() {
  local cores load1
  cores="$(get_cpu_cores)"
  load1="$(get_load_1min)"

  local is_peak
  is_peak="$("$PYTHON_BIN" -c "import sys; print(1 if float('$load1') > float('${TELEMETRY_LOAD_PEAK}') else 0)" 2>/dev/null || echo 0)"
  if [[ "$is_peak" == "1" ]]; then
    TELEMETRY_LOAD_PEAK="$load1"
  fi

  local mod_limit high_limit
  mod_limit="$("$PYTHON_BIN" -c "print($cores * 0.7)" 2>/dev/null || echo "1.0")"
  high_limit="$("$PYTHON_BIN" -c "print($cores * 1.1)" 2>/dev/null || echo "2.0")"

  local is_high is_mod
  is_high="$("$PYTHON_BIN" -c "import sys; print(1 if float('$load1') >= float('$high_limit') else 0)" 2>/dev/null || echo 0)"
  is_mod="$("$PYTHON_BIN" -c "import sys; print(1 if float('$load1') >= float('$mod_limit') else 0)" 2>/dev/null || echo 0)"

  if [[ "$is_high" == "1" ]]; then
    TELEMETRY_THROTTLE_MODE="high_load_local"
    log "WARN high_load_local: load1=${load1} >= limit=${high_limit} (${cores} cores). Sleeping ${THROTTLE_HIGH_SLEEP}s..."
    sleep "$THROTTLE_HIGH_SLEEP"
    TELEMETRY_THROTTLE_SLEEPS="$("$PYTHON_BIN" -c "print(round(float('${TELEMETRY_THROTTLE_SLEEPS}') + float('${THROTTLE_HIGH_SLEEP}'), 2))" 2>/dev/null || echo "${TELEMETRY_THROTTLE_SLEEPS}")"
    return 2
  elif [[ "$is_mod" == "1" ]]; then
    if [[ "$TELEMETRY_THROTTLE_MODE" != "high_load_local" ]]; then
      TELEMETRY_THROTTLE_MODE="throttled_local"
    fi
    sleep "$THROTTLE_MODERATE_SLEEP"
    TELEMETRY_THROTTLE_SLEEPS="$("$PYTHON_BIN" -c "print(round(float('${TELEMETRY_THROTTLE_SLEEPS}') + float('${THROTTLE_MODERATE_SLEEP}'), 2))" 2>/dev/null || echo "${TELEMETRY_THROTTLE_SLEEPS}")"
    return 1
  fi
  return 0
}

acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
      log "INFO: ya hay una corrida en progreso, saliendo."
      exit 0
    fi
  else
    if [[ -f "${LOCK_FILE}.pid" ]] && kill -0 "$(cat "${LOCK_FILE}.pid")" 2>/dev/null; then
      log "INFO: ya hay una corrida en progreso (pidfile), saliendo."
      exit 0
    fi
    echo $$ > "${LOCK_FILE}.pid"
    trap 'rm -f "${LOCK_FILE}.pid" 2>/dev/null || true' EXIT
  fi
}

detect_mode() {
  if [[ "$MODE" != "auto" ]]; then
    echo "$MODE"; return
  fi
  if [[ -d /usr/local/cpanel ]]; then
    echo "cpanel"; return
  fi
  if [[ -d /usr/local/directadmin ]]; then
    echo "directadmin"; return
  fi
  echo "auto"
}

purge_spool() {
  rm -rf "${SPOOL_DIR:?}/"* 2>/dev/null || true
}

reset_states() {
  rm -f "${STATE_DIR:?}/"*.state 2>/dev/null || true
  rm -f "${STATE_DIR:?}/"sar_backfill_done_* 2>/dev/null || true
}

reset_for_next_run_due_to_failure() {
  log "WARN backend_failure: spool PRESERVADO. El offset será retomado en la próxima ejecución."
  set_agent_state "delayed"
}

AGENT_STATE_FILE="${STATE_DIR}/agent_state.json"
AGENT_STATE="healthy"

set_agent_state() {
  local new_state="$1"
  local reason="${2:-}"
  AGENT_STATE="$new_state"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  cat > "$AGENT_STATE_FILE" <<EOF
{
  "state": "${new_state}",
  "reason": "${reason}",
  "timestamp_utc": "${ts}",
  "pid": $$,
  "version": "2.1.0-enterprise",
  "spool_dir": "${SPOOL_DIR}",
  "state_dir": "${STATE_DIR}"
}
EOF
  log "AGENT_STATE state=${new_state} reason=${reason}"
}

check_spool_size() {
  local spool_bytes
  local spool_warn_bytes=$(( ${SENTINELX_SPOOL_WARN_MB:-500} * 1024 * 1024 ))
  local spool_crit_bytes=$(( ${SENTINELX_SPOOL_CRIT_MB:-1024} * 1024 * 1024 ))

  shopt -s nullglob
  local jobs=( "${SPOOL_DIR}"/* )
  shopt -u nullglob

  if [[ ${#jobs[@]} -eq 0 ]]; then
    return 0
  fi

  spool_bytes="$(du -sb "${SPOOL_DIR}" 2>/dev/null | awk '{print $1}' || echo 0)"

  if (( spool_bytes >= spool_crit_bytes )); then
    set_agent_state "spool_critical" "spool_bytes=${spool_bytes} >= critical_limit=${spool_crit_bytes}"
    return 2
  elif (( spool_bytes >= spool_warn_bytes )); then
    set_agent_state "spool_warning" "spool_bytes=${spool_bytes} >= warn_limit=${spool_warn_bytes}"
    return 1
  fi
  return 0
}

backend_reachable() {
  local http_code
  http_code="$(curl -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$CONNECT_TIMEOUT" -H "X-API-Key: ${SENTINELX_API_KEY}" -o /dev/null -w "%{http_code}" -I "$SENTINELX_INGEST_URL" || true)"

  if [[ -z "$http_code" || "$http_code" == "000" ]]; then
    set_agent_state "offline" "no_http_response connect_timeout=${CONNECT_TIMEOUT}s"
    return 1
  fi

  if [[ "$http_code" == "401" || "$http_code" == "403" ]]; then
    set_agent_state "authentication_failed" "http_code=${http_code}"
    return 1
  fi

  if [[ "$http_code" == "405" || "$http_code" == "422" || "$http_code" =~ ^2 || "$http_code" =~ ^3 || "$http_code" == "404" ]]; then
    set_agent_state "healthy"
    return 0
  fi

  if [[ "$http_code" == "429" || "$http_code" =~ ^5 ]]; then
    set_agent_state "delayed" "backend_degraded http_code=${http_code}"
    return 1
  fi

  set_agent_state "healthy"
  return 0
}

curl_upload_file() {
  local tag="$1"
  local filepath="$2"
  local filename="$3"

  check_throttling_and_load || true

  local resp_body_file
  resp_body_file="$(mktemp "${TMP_DIR}/curl_resp.XXXXXX" 2>/dev/null || echo "${TMP_DIR}/curl_resp.tmp")"

  local t_start t_end lat_ms
  t_start="$(get_time_ms)"

  local curl_args=(
    -sS
    --connect-timeout "$CONNECT_TIMEOUT"
    --max-time "$MAX_TIME"
    -H "X-API-Key: ${SENTINELX_API_KEY}"
    -F "tag=${tag}"
    -F "file=@${filepath};filename=${filename}"
    -o "$resp_body_file"
    -w "
%{http_code}"
  )

  if [[ -n "$LIMIT_RATE" ]]; then
    curl_args+=(--limit-rate "$LIMIT_RATE")
  fi

  local curl_exit=0
  local curl_out
  curl_out="$(curl "${curl_args[@]}" "$SENTINELX_INGEST_URL" 2>&1)" || curl_exit=$?

  t_end="$(get_time_ms)"

  if (( t_start > 0 && t_end >= t_start )); then
    lat_ms=$(( t_end - t_start ))
  else
    lat_ms=0
  fi

  TELEMETRY_HTTP_REQUESTS=$(( TELEMETRY_HTTP_REQUESTS + 1 ))
  TELEMETRY_LATENCY_SUM_MS=$(( TELEMETRY_LATENCY_SUM_MS + lat_ms ))

  local http_code
  http_code="$(echo "$curl_out" | tail -n1 | grep -E '^[0-9]{3}$' || echo "000")"
  LAST_HTTP_CODE="$http_code"
  LAST_CURL_EXIT="$curl_exit"

  if [[ "$http_code" == "200" || "$http_code" == "201" || "$http_code" == "202" ]]; then
    rm -f "$resp_body_file" 2>/dev/null || true
    TELEMETRY_JOBS_SENT=$(( TELEMETRY_JOBS_SENT + 1 ))

    if (( lat_ms >= BACKEND_LATENCY_THRESHOLD_MS )); then
      TELEMETRY_THROTTLE_MODE="backpressure_backend"
      log "WARN backpressure_backend: HTTP latencia alta (${lat_ms}ms >= ${BACKEND_LATENCY_THRESHOLD_MS}ms). Sleeping ${THROTTLE_MODERATE_SLEEP}s..."
      sleep "$THROTTLE_MODERATE_SLEEP"
      TELEMETRY_THROTTLE_SLEEPS="$("$PYTHON_BIN" -c "print(round(float('${TELEMETRY_THROTTLE_SLEEPS}') + float('${THROTTLE_MODERATE_SLEEP}'), 2))" 2>/dev/null || echo "${TELEMETRY_THROTTLE_SLEEPS}")"
    fi
    return 0
  fi

  TELEMETRY_HTTP_FAILURES=$(( TELEMETRY_HTTP_FAILURES + 1 ))

  if [[ "$http_code" == "429" || "$http_code" == "502" || "$http_code" == "503" || "$http_code" == "504" ]]; then
    TELEMETRY_THROTTLE_MODE="backpressure_backend"
    log "WARN backend_rate_limit_or_error: HTTP ${http_code} recibido. Aplicando Backoff Exponencial (2.0s)..."
    sleep 2.0
    TELEMETRY_THROTTLE_SLEEPS="$("$PYTHON_BIN" -c "print(round(float('${TELEMETRY_THROTTLE_SLEEPS}') + 2.0, 2))" 2>/dev/null || echo "${TELEMETRY_THROTTLE_SLEEPS}")"
  fi

  local body_snippet=""
  if [[ -f "$resp_body_file" ]]; then
    body_snippet="$(head -c 150 "$resp_body_file" | tr '
' ' ' | tr -d '')"
    rm -f "$resp_body_file" 2>/dev/null || true
  fi

  local failure_reason="unknown"
  case "$http_code" in
    000) failure_reason="NETWORK_TIMEOUT_OR_CONNECTION_REFUSED (curl_exit=${curl_exit})" ;;
    400) failure_reason="BAD_REQUEST (payload corrupt or invalid tag)" ;;
    401|403) failure_reason="AUTH_FAILURE (invalid API Key)" ;;
    413) failure_reason="PAYLOAD_TOO_LARGE (exceeds webserver body limit)" ;;
    429) failure_reason="RATE_LIMITED (too many requests)" ;;
    500|502|503|504) failure_reason="BACKEND_SERVER_ERROR (HTTP ${http_code})" ;;
    *) failure_reason="HTTP_ERROR_${http_code}" ;;
  esac

  LAST_FAILURE_REASON="$failure_reason"
  log "ERROR upload tag=${tag} file=${filename} http_code=${http_code} curl_exit=${curl_exit} reason=[${failure_reason}] response=[${body_snippet}]"
  return 1
}

state_key_from_path() {
  local path="$1"
  echo "$(echo "$path" | sed 's#[^a-zA-Z0-9._-]#_#g')"
}
state_file_for_path() {
  local path="$1"
  echo "${STATE_DIR}/$(state_key_from_path "$path").state"
}
read_state() {
  local path="$1"
  local sf
  sf="$(state_file_for_path "$path")"
  if [[ -f "$sf" ]]; then
    cat "$sf"
  else
    echo "0 0"
  fi
}
write_state() {
  local path="$1"
  local inode="$2"
  local offset="$3"
  local sf
  sf="$(state_file_for_path "$path")"
  printf "%s %s
" "$inode" "$offset" > "$sf"
}

py_align_cursor() {
  local path="$1"
  local off="$2"
  local scan_back="$3"

  "$PYTHON_BIN" - "$path" "$off" "$scan_back" <<'PY'
import sys
p = sys.argv[1]
off = int(sys.argv[2])
scan_back = int(sys.argv[3])

if off <= 0:
    print(0); sys.exit()

start = max(0, off - scan_back)
with open(p, "rb") as f:
    f.seek(start)
    buf = f.read(off - start)

idx = buf.rfind(b"
")
if idx != -1:
    print(start + idx + 1)
else:
    print(off)
PY
}

py_choose_end_aligned() {
  local path="$1"
  local cursor="$2"
  local proposed_end="$3"
  local target_size="$4"
  local scan_back="$5"
  local scan_fwd="$6"

  "$PYTHON_BIN" - "$path" "$cursor" "$proposed_end" "$target_size" "$scan_back" "$scan_fwd" <<'PY'
import sys

p = sys.argv[1]
cursor = int(sys.argv[2])
proposed_end = int(sys.argv[3])
target_size = int(sys.argv[4])
scan_back = int(sys.argv[5])
scan_fwd = int(sys.argv[6])

if proposed_end > target_size:
    proposed_end = target_size
if proposed_end <= cursor:
    print(cursor); raise SystemExit

win_start = max(cursor, proposed_end - scan_back)
with open(p, "rb") as f:
    f.seek(win_start)
    data = f.read(proposed_end - win_start)

idx = data.rfind(b"
")
if idx != -1:
    end = win_start + idx + 1
    if end > cursor:
        print(end); raise SystemExit

fwd_end = min(target_size, proposed_end + scan_fwd)
if fwd_end > proposed_end:
    with open(p, "rb") as f:
        f.seek(proposed_end)
        data2 = f.read(fwd_end - proposed_end)
    j = data2.find(b"
")
    if j != -1:
        print(proposed_end + j + 1); raise SystemExit

print(cursor)
PY
}

get_first_run_lines_for_path() {
  local path="$1"

  case "$path" in
    /var/log/secure|/var/log/messages|/var/log/exim_mainlog|    /var/log/maillog|/var/log/mail.log|/var/log/lfd.log|    /usr/local/apache/logs/*|/usr/local/cpanel/logs/*|    /var/log/httpd/*|/var/log/apache2/*)
      echo "$FIRST_RUN_CONTEXT_LINES"; return ;;
  esac

  local mtime now age
  mtime="$(stat -c '%Y' "$path" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  age=$(( now - mtime ))

  if   (( age < 86400   )); then echo "$NGINX_DOMAIN_LINES_ACTIVE"    # <24h
  elif (( age < 604800  )); then echo "$NGINX_DOMAIN_LINES_RECENT"    # 1-7 días
  else                           echo "$NGINX_DOMAIN_LINES_INACTIVE"  # >7 días
  fi
}

initial_offset_for_first_run() {
  local path="$1"
  local size
  size="$(stat -c '%s' "$path" 2>/dev/null || echo 0)"
  (( size > 0 )) || { echo 0; return; }

  local context_lines
  context_lines="$(get_first_run_lines_for_path "$path")"

  local scan_bytes=$(( FIRST_RUN_SCAN_MB * 1024 * 1024 ))
  local fallback_bytes=$(( FIRST_RUN_BACKFILL_MB * 1024 * 1024 ))

  "$PYTHON_BIN" - "$path" "$size" "$context_lines" "$scan_bytes" "$fallback_bytes" <<'PY'
import sys

p = sys.argv[1]
size = int(sys.argv[2])
context_lines = int(sys.argv[3])
scan_bytes = int(sys.argv[4])
fallback_bytes = int(sys.argv[5])

start = max(0, size - scan_bytes)
with open(p, "rb") as f:
    f.seek(start)
    buf = f.read(size - start)

if b"
" not in buf:
    print(max(0, size - fallback_bytes))
    raise SystemExit

newline_positions = [i for i,b in enumerate(buf) if b == 10]

if len(newline_positions) <= context_lines:
    print(start)
    raise SystemExit

cut_nl_idx = newline_positions[-(context_lines+1)]
out = start + cut_nl_idx + 1
print(out)
PY
}

spool_job_dir() {
  local tag="$1"
  local name="$2"
  local ts
  ts="$(date -u +%s)"
  local h
  h="$(echo "${tag}:${name}:${ts}:$$" | sha1sum | awk '{print $1}')"
  echo "${SPOOL_DIR}/${ts}__${tag}__${h}"
}

enqueue_payload_file() {
  local tag="$1"
  local src_path="$2"
  local orig_name="$3"
  local inode="$4"
  local start_off="$5"
  local end_off="$6"
  local raw_bytes="$7"
  local payload_path="$8"

  local job
  job="$(spool_job_dir "$tag" "$orig_name")"
  mkdir -p "$job"

  local payload_size
  payload_size="$(stat -c '%s' "$payload_path" 2>/dev/null || echo 0)"

  cat > "${job}/meta.env" <<EOF
TAG=$(printf '%q' "$tag")
ORIG_NAME=$(printf '%q' "$orig_name")
SRC_PATH=$(printf '%q' "$src_path")
INODE=$(printf '%q' "$inode")
START_OFF=$(printf '%q' "$start_off")
END_OFF=$(printf '%q' "$end_off")
RAW_BYTES=$(printf '%q' "$raw_bytes")
BYTES=$(printf '%q' "$payload_size")
EOF

  mv "$payload_path" "${job}/payload.gz"

  # ATOMICIDAD ESTRICTA: Confirmar persistencia duradera en spool ANTES de actualizar offset state
  if [[ -f "${job}/payload.gz" && -f "${job}/meta.env" ]]; then
    if [[ -n "${src_path:-}" && "$src_path" != "/dev/null" ]]; then
      write_state "$src_path" "$inode" "$end_off"
    fi
    TELEMETRY_JOBS_ENQUEUED=$(( TELEMETRY_JOBS_ENQUEUED + 1 ))
    TELEMETRY_RAW_BYTES=$(( TELEMETRY_RAW_BYTES + raw_bytes ))
    TELEMETRY_COMPRESSED_BYTES=$(( TELEMETRY_COMPRESSED_BYTES + payload_size ))
    TOTAL_FIRST_RUN_ENQUEUED_BYTES=$(( TOTAL_FIRST_RUN_ENQUEUED_BYTES + payload_size ))
  fi

  log "ENQUEUE tag=${tag} name=${orig_name} payload_bytes=${payload_size} raw_bytes=${raw_bytes} off=${start_off}-${end_off} job=$(basename "$job")"
}

flush_spool() {
  shopt -s nullglob
  local jobs=( "${SPOOL_DIR}"/* )
  shopt -u nullglob

  [[ ${#jobs[@]} -eq 0 ]] && return 0
  IFS=$'
' jobs=( $(printf "%s
" "${jobs[@]}" | sort) ); unset IFS

  for job in "${jobs[@]}"; do
    [[ -d "$job" ]] || continue
    # shellcheck disable=SC1090
    source "${job}/meta.env"

    local payload="${job}/payload.gz"
    if [[ ! -f "$payload" ]]; then
      log "WARN spool job without payload: $job"
      rm -rf "$job"
      continue
    fi

    if time_exceeded; then
      TELEMETRY_STOP_REASON="max_seconds_reached"
      log "STOP flush_spool time_exceeded"
      return 0
    fi

    local fname="${ORIG_NAME}.part_${START_OFF}_${END_OFF}.gz"

    if curl_upload_file "$TAG" "$payload" "$fname"; then
      if [[ -n "${SRC_PATH:-}" && "$SRC_PATH" != "/dev/null" ]]; then
        local cur_inode cur_off
        read -r cur_inode cur_off < <(read_state "$SRC_PATH")

        if [[ "$cur_inode" == "$INODE" ]]; then
          if (( END_OFF > cur_off )); then
            write_state "$SRC_PATH" "$INODE" "$END_OFF"
          fi
        else
          write_state "$SRC_PATH" "$INODE" "$END_OFF"
        fi
      fi

      rm -rf "$job"
      if [[ "$SLEEP_BETWEEN" != "0" ]]; then
        sleep "$SLEEP_BETWEEN"
      fi
    else
      if [[ "${LAST_HTTP_CODE:-}" == "400" || "${LAST_HTTP_CODE:-}" == "422" ]]; then
        log "WARN discarding unprocessable spool job (HTTP ${LAST_HTTP_CODE}): $(basename "$job")"
        rm -rf "$job"
        continue
      fi
      log "STOP flush_spool due to send failure (job=$(basename "$job"), HTTP ${LAST_HTTP_CODE:-unknown}, curl_exit=${LAST_CURL_EXIT:-0}, reason=[${LAST_FAILURE_REASON:-unknown}])"
      if [[ "$RESET_ON_SEND_FAILURE" == "1" ]]; then
        reset_for_next_run_due_to_failure
      fi
      return 1
    fi
  done

  return 0
}

process_file_up_to_target() {
  local path="$1"
  local tag="$2"
  local name="$3"

  [[ -f "$path" ]] || return 0

  TELEMETRY_FILES_SCANNED=$(( TELEMETRY_FILES_SCANNED + 1 ))

  local quick_size quick_inode
  quick_size="$(stat -c '%s' "$path" 2>/dev/null || echo 0)"
  quick_inode="$(stat -c '%i' "$path" 2>/dev/null || echo 0)"

  local qs_inode qs_off
  read -r qs_inode qs_off < <(read_state "$path")

  if [[ "$qs_inode" != "0" && "$quick_inode" == "$qs_inode" && "$quick_size" -le "$qs_off" ]]; then
    return 0
  fi

  TELEMETRY_FILES_CHANGED=$(( TELEMETRY_FILES_CHANGED + 1 ))

  # Límite Global FIRST_RUN_MAX_TOTAL_MB en primer arranque
  local max_first_run_bytes=$(( FIRST_RUN_MAX_TOTAL_MB * 1024 * 1024 ))
  if [[ "$qs_inode" == "0" && "$qs_off" == "0" ]]; then
    if (( TOTAL_FIRST_RUN_ENQUEUED_BYTES >= max_first_run_bytes )); then
      TELEMETRY_STOP_REASON="max_payload_reached"
      log "INFO max_payload_reached: FIRST_RUN_MAX_TOTAL_MB (${FIRST_RUN_MAX_TOTAL_MB}MB) alcanzado en esta corrida. Retomando restantes en próxima ejecución."
      return 0
    fi
  fi

  # Verificación de High Load Local
  local current_load_st=0
  check_throttling_and_load || current_load_st=$?
  if [[ "$current_load_st" == "2" ]]; then
    TELEMETRY_STOP_REASON="high_load_triggered"
    log "WARN high_load_triggered: deteniendo encolado adicional de bootstrap en esta corrida."
    return 0
  fi

  local target_size="$quick_size"
  local inode="$quick_inode"
  local st_inode="$qs_inode"
  local st_off="$qs_off"

  (( target_size > 0 )) || return 0

  local cursor_off
  if [[ "$st_inode" == "0" && "$st_off" == "0" ]]; then
    cursor_off="$(initial_offset_for_first_run "$path")"
  else
    if [[ "$inode" != "$st_inode" || "$target_size" -lt "$st_off" ]]; then
      cursor_off=0
    else
      cursor_off="$st_off"
    fi
  fi

  (( cursor_off >= target_size )) && return 0

  cursor_off="$(py_align_cursor "$path" "$cursor_off" "$MAX_NEWLINE_SCAN_BYTES" || echo 0)"
  [[ "$cursor_off" =~ ^[0-9]+$ ]] || cursor_off=0
  (( cursor_off >= target_size )) && return 0

  local chunk_bytes=$((CHUNK_MB * 1024 * 1024))

  while (( cursor_off < target_size )); do
    if time_exceeded; then
      TELEMETRY_STOP_REASON="max_seconds_reached"
      log "STOP time_exceeded while enqueuing $path"
      return 0
    fi

    local proposed_end=$((cursor_off + chunk_bytes))
    (( proposed_end > target_size )) && proposed_end="$target_size"

    local end_off
    end_off="$(py_choose_end_aligned "$path" "$cursor_off" "$proposed_end" "$target_size" "$MAX_NEWLINE_SCAN_BYTES" "$MAX_FORWARD_SCAN_BYTES" || echo "$cursor_off")"
    [[ "$end_off" =~ ^[0-9]+$ ]] || end_off="$cursor_off"

    if (( end_off <= cursor_off )); then
      return 0
    fi

    local bytes=$((end_off - cursor_off))
    (( bytes > 0 )) || return 0

    local tmp_gz="${TMP_DIR}/$(basename "$path").${cursor_off}-${end_off}.gz"

    if ! dd if="$path" iflag=skip_bytes,count_bytes skip="$cursor_off" count="$bytes" status=none         | gzip -c > "$tmp_gz"; then
      rm -f "$tmp_gz"
      log "WARN enqueue failed path=$path"
      return 0
    fi

    enqueue_payload_file "$tag" "$path" "$name" "$inode" "$cursor_off" "$end_off" "$bytes" "$tmp_gz"
    cursor_off="$end_off"
    TELEMETRY_FILES_PROCESSED=$(( TELEMETRY_FILES_PROCESSED + 1 ))
  done
}

sar_header() {
  local sar_date="$1"
  local sar_file="$2"
  local sar_mode="$3"
  local gen_at
  gen_at="$(date -u +"%Y-%m-%d %H:%M:%S")"
  cat <<EOF
SAR_DATE=${sar_date}
SAR_FILE=${sar_file}
SAR_MODE=${sar_mode}
GENERATED_AT_UTC=${gen_at}
----------------------------------------
EOF
}

fmt_date_from_sa_filename() {
  local f="$1"
  date -u -r "$f" +"%Y-%m-%d" 2>/dev/null || echo "$(date -u +"%Y-%m-%d")"
}

enqueue_sar_for_file() {
  local sa_file="$1"
  local mode="$2"
  [[ -f "$sa_file" ]] || return 0
  time_exceeded && return 0

  local sar_date
  sar_date="$(fmt_date_from_sa_filename "$sa_file")"

  local out="${TMP_DIR}/sar_$(basename "$sa_file")_${mode//-/}.txt"
  {
    sar_header "$sar_date" "$sa_file" "$mode"
    sar -f "$sa_file" "$mode" 2>&1 || true
  } > "$out"

  local gz="${out}.gz"
  gzip -c "$out" > "$gz"
  rm -f "$out"

  enqueue_payload_file "sar" "/dev/null" "sar_${sar_date}_$(basename "$sa_file")_${mode}" "0" 0 0 0 "$gz"
}

enqueue_sar_live() {
  local mode="$1"
  time_exceeded && return 0

  local sar_date
  sar_date="$(date -u +"%Y-%m-%d")"

  local out="${TMP_DIR}/sar_live_${sar_date}_${mode//-/}.txt"
  {
    sar_header "$sar_date" "" "$mode"
    sar "$mode" 2>&1 || true
  } > "$out"

  local gz="${out}.gz"
  gzip -c "$out" > "$gz"
  rm -f "$out"

  enqueue_payload_file "sar" "/dev/null" "sar_live_${sar_date}_${mode}" "0" 0 0 0 "$gz"
}

sar_send_logic() {
  command -v sar >/dev/null 2>&1 || { log "WARN: sar no está disponible (instala sysstat)."; return 0; }

  enqueue_sar_live "-q"
  enqueue_sar_live "-r"
  enqueue_sar_live "-d"

  if [[ "${SAR_BACKFILL_DAYS}" =~ ^[0-9]+$ ]] && (( SAR_BACKFILL_DAYS > 0 )); then
    local marker="${STATE_DIR}/sar_backfill_done_${SAR_BACKFILL_DAYS}"
    if [[ ! -f "$marker" ]]; then
      local i
      for (( i=0; i<=SAR_BACKFILL_DAYS; i++ )); do
        time_exceeded && break
        local dd
        dd="$(date -u -d "-${i} day" +%d 2>/dev/null || true)"
        [[ -n "$dd" ]] || continue
        local f="/var/log/sa/sa${dd}"
        enqueue_sar_for_file "$f" "-q"
        enqueue_sar_for_file "$f" "-r"
        enqueue_sar_for_file "$f" "-d"
      done
      touch "$marker"
    else
      local today_dd
      today_dd="$(date -u +%d)"
      enqueue_sar_for_file "/var/log/sa/sa${today_dd}" "-q"
      enqueue_sar_for_file "/var/log/sa/sa${today_dd}" "-r"
      enqueue_sar_for_file "/var/log/sa/sa${today_dd}" "-d"
    fi
  fi
}

DOMAIN_CACHE_FILE=""

_init_domain_cache_path() {
  DOMAIN_CACHE_FILE="${STATE_DIR}/nginx_domains.cache"
}

_maybe_refresh_domain_cache() {
  _init_domain_cache_path
  local age=999999
  if [[ -f "$DOMAIN_CACHE_FILE" ]]; then
    local mtime
    mtime="$(stat -c '%Y' "$DOMAIN_CACHE_FILE" 2>/dev/null || echo 0)"
    age=$(( $(date +%s) - mtime ))
  fi
  if (( age >= DOMAIN_CACHE_TTL )); then
    find /var/log/nginx/domains/ -maxdepth 1 -type f       ! -name '*.gz'       ! -name '*.[0-9]'       ! -name '*-bytes_log'       -printf 'nginx_access:%p:nginx_domain_%f
'       > "${DOMAIN_CACHE_FILE}.tmp" 2>/dev/null       && mv "${DOMAIN_CACHE_FILE}.tmp" "$DOMAIN_CACHE_FILE"       || true
  fi
}

collect_log_sources() {
  local mode_detected="$1"

  echo "system:/var/log/messages:system_messages"
  echo "secure:/var/log/secure:secure"
  echo "lfd:/var/log/lfd.log:lfd"
  echo "exim_mainlog:/var/log/exim_mainlog:exim_mainlog"
  echo "maillog:/var/log/maillog:maillog"
  echo "maillog:/var/log/mail.log:mail_log"

  [[ -f "/var/log/nginx/access.log" ]] && echo "nginx_access:/var/log/nginx/access.log:nginx_access"
  [[ -f "/var/log/nginx/error.log" ]] && echo "nginx_error:/var/log/nginx/error.log:nginx_error"

  if [[ -d "/var/log/nginx/domains" ]]; then
    _maybe_refresh_domain_cache
    [[ -f "$DOMAIN_CACHE_FILE" ]] && cat "$DOMAIN_CACHE_FILE"
  fi

  if [[ "$mode_detected" == "directadmin" || "$mode_detected" == "auto" ]]; then
    echo "apache_access:/var/log/httpd/access_log:apache_access"
    echo "apache_error:/var/log/httpd/error_log:apache_error"
    echo "apache_access:/var/log/apache2/access.log:apache2_access"
    echo "apache_error:/var/log/apache2/error.log:apache2_error"
  fi

  if [[ "$mode_detected" == "cpanel" || "$mode_detected" == "auto" ]]; then
    echo "apache_access:/usr/local/apache/logs/access_log:apache_access"
    echo "apache_error:/usr/local/apache/logs/error_log:apache_error"
    echo "modsec:/usr/local/apache/logs/modsec_audit.log:modsec_audit"
    echo "cpanel_access:/usr/local/cpanel/logs/access_log:cpanel_access"
  fi
}

main() {
  acquire_lock
  need_python

  renice +10 $$ >/dev/null 2>&1 || true
  ionice -c2 -n7 -p $$ >/dev/null 2>&1 || true

  local mode_detected
  mode_detected="$(detect_mode)"

  local load_start
  load_start="$(get_load_1min)"
  TELEMETRY_LOAD_PEAK="$load_start"

  log "START mode=${mode_detected} first_run=tail_lines context_lines=${FIRST_RUN_CONTEXT_LINES} scan_mb=${FIRST_RUN_SCAN_MB} fallback_mb=${FIRST_RUN_BACKFILL_MB} max_first_run_mb=${FIRST_RUN_MAX_TOTAL_MB} chunk_mb=${CHUNK_MB} max_seconds=${MAX_SECONDS_PER_RUN} python=$("$PYTHON_BIN" -V 2>&1 | tr -d '')"

  check_spool_size || true

  if ! backend_reachable; then
    if [[ "$RESET_ON_BACKEND_DOWN" == "1" ]]; then
      log "WARN backend_unhealthy: RESET_ON_BACKEND_DOWN=1 - PURGA DE SPOOL (PELIGROSO)."
      purge_spool
      reset_states
    else
      log "INFO backend_unhealthy: spool PRESERVADO. Se reintentará en la próxima ejecución."
    fi
    TELEMETRY_STOP_REASON="backend_unhealthy"
    log "END (backend unhealthy - spool preserved)"
    return 0
  fi

  # 1) manda lo pendiente del spool primero
  if ! flush_spool; then
    if [[ "$RESET_ON_SEND_FAILURE" == "1" ]]; then
      log "WARN flush_failed con RESET_ON_SEND_FAILURE=1: PURGA DE SPOOL (PELIGROSO)."
      purge_spool
      reset_states
    else
      log "WARN flush_failed: spool PRESERVADO. Se reintentará en la próxima ejecución."
    fi
    TELEMETRY_STOP_REASON="flush_failed"
    log "END (flush failed - spool preserved)"
    return 0
  fi

  # 2) encola por archivo hasta su snapshot
  while IFS=: read -r tag path name; do
    [[ -n "${tag:-}" && -n "${path:-}" && -n "${name:-}" ]] || continue
    [[ -f "$path" ]] || continue

    if time_exceeded; then
      TELEMETRY_STOP_REASON="max_seconds_reached"
      log "STOP time_exceeded before finishing sources"
      break
    fi

    process_file_up_to_target "$path" "$tag" "$name"

    if [[ "$TELEMETRY_STOP_REASON" == "max_payload_reached" || "$TELEMETRY_STOP_REASON" == "high_load_triggered" ]]; then
      break
    fi
  done < <(collect_log_sources "$mode_detected")

  # 3) SAR si hay tiempo
  if ! time_exceeded && [[ "$TELEMETRY_STOP_REASON" == "completed" ]]; then
    sar_send_logic
  fi

  # 4) flush final
  if ! flush_spool; then
    if [[ "$RESET_ON_SEND_FAILURE" == "1" ]]; then
      log "WARN final_flush_failed con RESET_ON_SEND_FAILURE=1: PURGA DE SPOOL."
      purge_spool
      reset_states
    else
      log "WARN final_flush_failed: spool PRESERVADO (HTTP ${LAST_HTTP_CODE:-000})."
    fi
    TELEMETRY_STOP_REASON="final_flush_failed"
    log "END (final flush failed - spool preserved)"
    return 0
  fi

  set_agent_state "healthy"

  # Resumen de Telemetría al finalizar
  local duration_sec=$(( $(date +%s) - RUN_START_EPOCH ))
  local cpu_cores
  cpu_cores="$(get_cpu_cores)"
  local load_end
  load_end="$(get_load_1min)"

  shopt -s nullglob
  local remaining_jobs=( "${SPOOL_DIR}"/* )
  shopt -u nullglob
  TELEMETRY_JOBS_PENDING=${#remaining_jobs[@]}

  local latency_avg=0
  if (( TELEMETRY_HTTP_REQUESTS > 0 )); then
    latency_avg=$(( TELEMETRY_LATENCY_SUM_MS / TELEMETRY_HTTP_REQUESTS ))
  fi

  log "TELEMETRY summary duration_sec=${duration_sec} cpu_cores=${cpu_cores} load_start=${load_start} load_end=${load_end} load_peak=${TELEMETRY_LOAD_PEAK} files_scanned=${TELEMETRY_FILES_SCANNED} files_changed=${TELEMETRY_FILES_CHANGED} files_processed=${TELEMETRY_FILES_PROCESSED} jobs_enqueued=${TELEMETRY_JOBS_ENQUEUED} jobs_sent=${TELEMETRY_JOBS_SENT} jobs_pending=${TELEMETRY_JOBS_PENDING} raw_bytes=${TELEMETRY_RAW_BYTES} compressed_bytes=${TELEMETRY_COMPRESSED_BYTES} http_requests=${TELEMETRY_HTTP_REQUESTS} http_failures=${TELEMETRY_HTTP_FAILURES} backend_latency_avg_ms=${latency_avg} throttle_mode=${TELEMETRY_THROTTLE_MODE} throttle_sleeps=${TELEMETRY_THROTTLE_SLEEPS} stop_reason=${TELEMETRY_STOP_REASON}"

  log "END success state=${AGENT_STATE}"
}

main "$@"
