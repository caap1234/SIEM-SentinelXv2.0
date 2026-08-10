# app/core/nats_config.py
"""
Configuración y Topología de Streams / Subjects de NATS JetStream para SentinelX SIEM.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

# NATS Connection URL
NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
if os.path.exists("/.dockerenv") and ("localhost" in NATS_URL or "127.0.0.1" in NATS_URL):
    NATS_URL = NATS_URL.replace("localhost", "nats").replace("127.0.0.1", "nats")

# Nombres de Streams
STREAM_RAW = "SENTINELX_INGEST_RAW"
STREAM_NORMALIZED = "SENTINELX_EVENTS_NORMALIZED"
STREAM_DLQ = "SENTINELX_DLQ"
STREAM_METRICS = "SENTINELX_METRICS"

# Subjects (Tópicos)
SUBJECT_RAW_HOSTING = "sentinelx.ingest.raw.hosting"
SUBJECT_NORMALIZED_HOSTING = "sentinelx.events.normalized.hosting"
SUBJECT_DLQ_PARSING = "sentinelx.dlq.parsing"
SUBJECT_DLQ_INDEXING = "sentinelx.dlq.indexing"
SUBJECT_METRICS_SYSTEM = "sentinelx.metrics.system"

# Consumidores Durables
CONSUMER_PARSER = "parser_worker_group"
CONSUMER_INDEXER = "opensearch_indexer_group"
CONSUMER_CORRELATION = "correlation_engine_group"
CONSUMER_DLQ = "dlq_monitor_group"

# Configuración de Topología JetStream
JETSTREAM_STREAMS: List[Dict[str, Any]] = [
    {
        "name": STREAM_RAW,
        "subjects": ["sentinelx.ingest.raw.*"],
        "max_age": 86400 * 7,  # 7 días de retención
        "storage": "file",
        "duplicate_window": 120,  # 2 minutos de ventana de deduplicación determinista
    },
    {
        "name": STREAM_NORMALIZED,
        "subjects": ["sentinelx.events.normalized.*"],
        "max_age": 86400 * 7,  # 7 días
        "storage": "file",
        "duplicate_window": 120,
    },
    {
        "name": STREAM_DLQ,
        "subjects": ["sentinelx.dlq.*"],
        "max_age": 86400 * 30,  # 30 días en DLQ para análisis forense/reprocesamiento
        "storage": "file",
    },
    {
        "name": STREAM_METRICS,
        "subjects": ["sentinelx.metrics.*"],
        "max_age": 86400 * 3,  # 3 días para métricas livianas
        "storage": "file",
    },
]
