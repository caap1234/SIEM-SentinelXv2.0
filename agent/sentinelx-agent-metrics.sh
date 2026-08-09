#!/usr/bin/env bash
# sentinelx-agent-metrics.sh
# Módulo de recolección de métricas de host para SentinelX Agent.
# Diseñado para ser sourced o ejecutado de forma independiente por sentinelx-agent.sh.
# NUNCA bloquea la entrega de logs si falla.
#
# Activación: SENTINELX_COLLECT_METRICS=1 (por defecto: 0 = desactivado)
# Variables de control:
#   SENTINELX_METRICS_CPU=1       CPU + Load Average
#   SENTINELX_METRICS_MEMORY=1    RAM + Swap
#   SENTINELX_METRICS_DISK=1      Uso de disco + inodos
#   SENTINELX_METRICS_IO=1        I/O de disco (iostat si disponible)
#   SENTINELX_METRICS_NET=1       Tráfico de red (tx/rx bytes por interfaz)
#   SENTINELX_METRICS_PROC=1      Top 10 procesos por CPU/RAM
#   SENTINELX_METRICS_SERVICES=1  Estado de servicios críticos (systemctl/service)
#   SENTINELX_METRICS_SPOOL=1     Estado del spool y del agente
#   SENTINELX_METRICS_TIMEOUT=10  Timeout en segundos para cada sección (default: 10)
#
set -uo pipefail

COLLECT_METRICS="${SENTINELX_COLLECT_METRICS:-0}"
METRICS_CPU="${SENTINELX_METRICS_CPU:-1}"
METRICS_MEMORY="${SENTINELX_METRICS_MEMORY:-1}"
METRICS_DISK="${SENTINELX_METRICS_DISK:-1}"
METRICS_IO="${SENTINELX_METRICS_IO:-0}"
METRICS_NET="${SENTINELX_METRICS_NET:-1}"
METRICS_PROC="${SENTINELX_METRICS_PROC:-1}"
METRICS_SERVICES="${SENTINELX_METRICS_SERVICES:-1}"
METRICS_SPOOL="${SENTINELX_METRICS_SPOOL:-1}"
METRICS_TIMEOUT="${SENTINELX_METRICS_TIMEOUT:-10}"

# Estado del spool y agente (inyectado por el agente principal)
SPOOL_DIR="${SPOOL_DIR:-/var/spool/sentinelx-agent}"
STATE_DIR="${STATE_DIR:-/var/lib/sentinelx-agent}"

# Helper para validar enteros
is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

# Genera un JSON de métricas del host y lo imprime por stdout.
collect_host_metrics() {
  [[ "$COLLECT_METRICS" != "1" ]] && return 0

  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local hostname
  hostname="$(hostname -s 2>/dev/null || echo 'unknown')"

  echo "{"
  echo "  \"@timestamp\": \"${ts}\","
  echo "  \"host\": {"
  echo "    \"name\": \"${hostname}\""
  echo "  },"
  echo "  \"event\": {"
  echo "    \"kind\": \"metric\","
  echo "    \"dataset\": \"sentinelx.metrics.system\","
  echo "    \"module\": \"agent\""
  echo "  },"

  # ── CPU / Load ─────────────────────────────────────────────────────────────
  if [[ "$METRICS_CPU" == "1" ]]; then
    local load1=0 load5=0 load15=0 cpus=1
    if [[ -f /proc/loadavg ]]; then
      read -r load1 load5 load15 _ < /proc/loadavg 2>/dev/null || true
    fi
    if command -v nproc >/dev/null 2>&1; then
      cpus="$(nproc 2>/dev/null || echo 1)"
    elif command -v sysctl >/dev/null 2>&1; then
      cpus="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    fi
    echo "  \"cpu\": {"
    echo "    \"load_1\": ${load1:-0},"
    echo "    \"load_5\": ${load5:-0},"
    echo "    \"load_15\": ${load15:-0},"
    echo "    \"cpus\": ${cpus:-1}"
    echo "  },"
  fi

  # ── Memory / Swap ───────────────────────────────────────────────────────────
  if [[ "$METRICS_MEMORY" == "1" ]]; then
    local mem_total=0 mem_avail=0 mem_free=0 swap_total=0 swap_free=0
    if [[ -f /proc/meminfo ]]; then
      mem_total="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
      mem_avail="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
      mem_free="$(awk '/^MemFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
      swap_total="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
      swap_free="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    fi
    echo "  \"memory\": {"
    echo "    \"total_kb\": ${mem_total:-0},"
    echo "    \"available_kb\": ${mem_avail:-0},"
    echo "    \"free_kb\": ${mem_free:-0}"
    echo "  },"
    echo "  \"swap\": {"
    echo "    \"total_kb\": ${swap_total:-0},"
    echo "    \"free_kb\": ${swap_free:-0}"
    echo "  },"
  fi

  # ── Disco ───────────────────────────────────────────────────────────────────
  if [[ "$METRICS_DISK" == "1" ]]; then
    echo "  \"disk\": ["
    local first=1
    while IFS= read -r line; do
      [[ "$line" =~ ^Filesystem || "$line" =~ ^Filesystem ]] && continue
      [[ -z "$line" ]] && continue
      local dev size used avail pct mount
      read -r dev size used avail pct mount <<< "$line"
      
      is_int "$size" || size=0
      is_int "$used" || used=0
      is_int "$avail" || avail=0

      [[ "$first" != "1" ]] && echo "  ,"
      echo "    {\"mount\": \"${mount:-unknown}\", \"size_kb\": ${size}, \"used_kb\": ${used}, \"avail_kb\": ${avail}, \"pct\": \"${pct:-0%}\"}"
      first=0
    done < <(df -k 2>/dev/null | grep -v "^tmpfs\|^devtmpfs\|^none\|^map" || true)
    echo "  ],"
  fi

  # ── Red ─────────────────────────────────────────────────────────────────────
  if [[ "$METRICS_NET" == "1" ]]; then
    echo "  \"network\": ["
    local first=1
    if [[ -f /proc/net/dev ]]; then
      while IFS=: read -r iface data; do
        iface="$(echo "$iface" | tr -d ' ')"
        [[ "$iface" == "lo" || -z "$iface" || "$iface" == "Inter" || "$iface" == "face" ]] && continue
        local rx_bytes tx_bytes
        rx_bytes="$(awk '{print $1}' <<< "$data")"
        tx_bytes="$(awk '{print $9}' <<< "$data")"
        is_int "$rx_bytes" || rx_bytes=0
        is_int "$tx_bytes" || tx_bytes=0
        [[ "$first" != "1" ]] && echo "  ,"
        echo "    {\"iface\": \"${iface}\", \"rx_bytes\": ${rx_bytes}, \"tx_bytes\": ${tx_bytes}}"
        first=0
      done < <(tail -n +3 /proc/net/dev 2>/dev/null || true)
    fi
    echo "  ],"
  fi

  # ── Estado del Spool y Agente ───────────────────────────────────────────────
  if [[ "$METRICS_SPOOL" == "1" ]]; then
    local spool_files spool_bytes agent_state
    shopt -s nullglob
    local spool_entries=( "${SPOOL_DIR}"/* )
    shopt -u nullglob
    spool_files="${#spool_entries[@]}"
    spool_bytes="$(du -sb "${SPOOL_DIR}" 2>/dev/null | awk '{print $1}' || echo 0)"
    is_int "$spool_bytes" || spool_bytes=0

    local state_raw=""
    if [[ -f "${STATE_DIR}/agent_state.json" ]]; then
      state_raw="$(cat "${STATE_DIR}/agent_state.json" 2>/dev/null | tr -d '\r\n' || echo '{}')"
    fi
    [[ -z "$state_raw" ]] && state_raw='{"state":"unknown"}'

    echo "  \"agent\": {"
    echo "    \"spool_files\": ${spool_files},"
    echo "    \"spool_bytes\": ${spool_bytes},"
    echo "    \"state\": ${state_raw}"
    echo "  },"
  fi

  echo "  \"_sentinel_metrics_version\": \"1.0.0\""
  echo "}"
}

# ─── Ejecución directa ────────────────────────────────────────────────────────
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  collect_host_metrics
fi
