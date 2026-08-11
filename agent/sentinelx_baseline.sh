#!/usr/bin/env bash
# sentinelx_baseline.sh
# Ejecutar en el servidor cliente ANTES y DESPUÉS de aplicar el Agent v1-optimizado.
# Guarda resultados en /tmp/sentinelx_baseline_<timestamp>.txt
set -euo pipefail

LABEL="${1:-v1}"
OUT="/tmp/sentinelx_baseline_${LABEL}_$(date +%Y%m%d_%H%M).txt"
ENV_FILE="/etc/sentinelx-agent.env"
AGENT_BIN="/usr/local/bin/sentinelx-agent.sh"

echo "=== SentinelX Agent Baseline: $LABEL ===" | tee "$OUT"
echo "Fecha UTC: $(date -u)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

# 1) Inventario de fuentes
echo "--- Fuentes de log ---" | tee -a "$OUT"
echo "Archivos en /var/log/nginx/domains: $(ls /var/log/nginx/domains/ 2>/dev/null | wc -l)" | tee -a "$OUT"
echo "  - Modificados <24h:  $(find /var/log/nginx/domains/ -mtime -1  -type f 2>/dev/null | wc -l)" | tee -a "$OUT"
echo "  - Modificados 1-7d:  $(find /var/log/nginx/domains/ -mtime +1 -mtime -7 -type f 2>/dev/null | wc -l)" | tee -a "$OUT"
echo "  - Sin cambio >7d:    $(find /var/log/nginx/domains/ -mtime +7  -type f 2>/dev/null | wc -l)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

# 2) Estado de resources antes de la corrida
echo "--- CPU/RAM antes ---" | tee -a "$OUT"
top -bn1 | grep -E "^(%Cpu|MiB Mem)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

# 3) I/O antes
echo "--- Disk I/O antes (iostat) ---" | tee -a "$OUT"
iostat -x 1 1 2>/dev/null | tail -20 | tee -a "$OUT" || echo "(iostat no disponible)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

# 4) Limpiar log para contar solo esta corrida
: > /var/log/sentinelx-agent.log 2>/dev/null || true

# 5) Ejecutar el agente y medir tiempo
echo "--- Corrida del agente ---" | tee -a "$OUT"
START_MS=$(date +%s%3N)
START_EPOCH=$(date +%s)

# Monitorear CPU en segundo plano durante la corrida
MONITOR_PID=""
{
  while true; do
    ps -p $$ -o %cpu= 2>/dev/null || true
    sleep 2
  done
} > /tmp/sentinelx_cpu_samples.txt &
MONITOR_PID=$!

ENV_FILE="$ENV_FILE" "$AGENT_BIN" 2>&1 | tee -a "$OUT"

kill "$MONITOR_PID" 2>/dev/null || true

END_MS=$(date +%s%3N)
DURATION_MS=$(( END_MS - START_MS ))

echo "" | tee -a "$OUT"
echo "--- Resultado ---" | tee -a "$OUT"
echo "Duración total:        ${DURATION_MS} ms  ($(( DURATION_MS / 1000 )) segundos)" | tee -a "$OUT"

# 6) Métricas del log generado
ENQUEUE_COUNT=$(grep -c "ENQUEUE"  /var/log/sentinelx-agent.log 2>/dev/null || echo 0)
SKIP_COUNT=$(grep -c "SKIP_NO_DELTA\|nada nuevo"  /var/log/sentinelx-agent.log 2>/dev/null || echo 0)
echo "Jobs ENQUEUE:          $ENQUEUE_COUNT" | tee -a "$OUT"
echo "Archivos skipeados:    $SKIP_COUNT (solo v1-opt en adelante)" | tee -a "$OUT"

# 7) I/O después
echo "" | tee -a "$OUT"
echo "--- Disk I/O después (iostat) ---" | tee -a "$OUT"
iostat -x 1 1 2>/dev/null | tail -20 | tee -a "$OUT" || true

# 8) Spool pendiente
SPOOL_JOBS=$(ls /var/spool/sentinelx-agent/ 2>/dev/null | wc -l)
echo "" | tee -a "$OUT"
echo "Jobs pendientes en spool: $SPOOL_JOBS" | tee -a "$OUT"

# 9) RAM del agente (peak)
echo "" | tee -a "$OUT"
echo "--- CPU samples durante corrida ---" | tee -a "$OUT"
awk '{sum+=$1; n++} END {if(n>0) printf "CPU promedio: %.1f%%\n", sum/n; else print "N/A"}' \
  /tmp/sentinelx_cpu_samples.txt | tee -a "$OUT"

echo "" | tee -a "$OUT"
echo "=== Baseline guardado en: $OUT ===" | tee -a "$OUT"
echo ""
echo "Comparte este archivo con el equipo SentinelX para análisis comparativo."
