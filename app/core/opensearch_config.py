# app/core/opensearch_config.py
"""
Configuración de OpenSearch, Index Templates ECS-compliant, Mappings y Políticas ISM.
"""
from __future__ import annotations

import os
from typing import Any, Dict

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
if os.path.exists("/.dockerenv") and ("localhost" in OPENSEARCH_URL or "127.0.0.1" in OPENSEARCH_URL):
    OPENSEARCH_URL = OPENSEARCH_URL.replace("localhost", "opensearch").replace("127.0.0.1", "opensearch")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"

INDEX_TEMPLATE_NAME = "sentinelx-events-template"
INDEX_PATTERN = "sentinelx-events-*"
ISM_POLICY_ID = "sentinelx-retention-policy"

# Mappings canónicos compatibles con ECS (Elastic Common Schema v1.0.0)
ECS_COMPONENT_MAPPINGS: Dict[str, Any] = {
    "properties": {
        "@timestamp": {"type": "date"},
        "schema": {
            "properties": {
                "name": {"type": "keyword"},
                "version": {"type": "keyword"},
            }
        },
        "event": {
            "properties": {
                "id": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "category": {"type": "keyword"},
                "type": {"type": "keyword"},
                "action": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "severity": {"type": "integer"},
                "risk_score": {"type": "float"},
                "dataset": {"type": "keyword"},
                "module": {"type": "keyword"},
                "original": {"type": "text"},
            }
        },
        "tenant": {
            "properties": {
                "id": {"type": "keyword"},
            }
        },
        "customer": {
            "properties": {
                "customer_id": {"type": "keyword"},
                "reseller_id": {"type": "keyword"},
                "account_id": {"type": "keyword"},
                "domain_name": {"type": "keyword"},
            }
        },
        "host": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "ip": {"type": "ip"},
                "os_name": {"type": "keyword"},
                "os_version": {"type": "keyword"},
            }
        },
        "agent": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "version": {"type": "keyword"},
            }
        },
        "service": {
            "properties": {
                "name": {"type": "keyword"},
                "type": {"type": "keyword"},
            }
        },
        "source": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "geo_country_iso_code": {"type": "keyword"},
                "as_number": {"type": "integer"},
                "as_organization_name": {"type": "keyword"},
            }
        },
        "destination": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
            }
        },
        "network": {
            "properties": {
                "transport": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "bytes": {"type": "long"},
                "packets": {"type": "long"},
            }
        },
        "user": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "domain": {"type": "keyword"},
            }
        },
        "process": {
            "properties": {
                "pid": {"type": "integer"},
                "name": {"type": "keyword"},
                "executable": {"type": "keyword"},
                "command_line": {"type": "text"},
            }
        },
        "file": {
            "properties": {
                "path": {"type": "keyword"},
                "name": {"type": "keyword"},
                "extension": {"type": "keyword"},
                "size": {"type": "long"},
                "hash_sha256": {"type": "keyword"},
            }
        },
        "url": {
            "properties": {
                "original": {"type": "text"},
                "path": {"type": "keyword"},
                "query": {"type": "keyword"},
                "domain": {"type": "keyword"},
            }
        },
        "http": {
            "properties": {
                "method": {"type": "keyword"},
                "status_code": {"type": "integer"},
                "referrer": {"type": "keyword"},
            }
        },
        "email": {
            "properties": {
                "from_address": {"type": "keyword"},
                "to_address": {"type": "keyword"},
                "subject": {"type": "text"},
                "message_id": {"type": "keyword"},
                "queue_id": {"type": "keyword"},
                "authenticated_user": {"type": "keyword"},
            }
        },
        "rule": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "category": {"type": "keyword"},
                "version": {"type": "keyword"},
            }
        },
        "log": {
            "properties": {
                "level": {"type": "keyword"},
                "file_path": {"type": "keyword"},
                "offset": {"type": "long"},
                "original": {"type": "text"},
            }
        },
        "labels": {"type": "object"},
        "tags": {"type": "keyword"},
    }
}

# Index Template con Data Stream habilitado
INDEX_TEMPLATE_BODY: Dict[str, Any] = {
    "index_patterns": [INDEX_PATTERN],
    "data_stream": {},
    "template": {
        "settings": {
            "index.number_of_shards": 1,
            "index.number_of_replicas": 0,
            "index.refresh_interval": "5s",
            "plugins.index_state_management.policy_id": ISM_POLICY_ID,
        },
        "mappings": ECS_COMPONENT_MAPPINGS,
    },
    "priority": 100,
}

# Política ISM (Index State Management) Retención Hot -> Warm -> Cold -> Delete
ISM_POLICY_BODY: Dict[str, Any] = {
    "policy": {
        "description": "Política de retención de datos SentinelX: Hot (7d) -> Warm (30d) -> Delete (90d)",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": {
                            "min_index_age": "7d"
                        }
                    }
                ]
            },
            {
                "name": "warm",
                "actions": [
                    {
                        "read_only": {}
                    }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "90d"
                        }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "delete": {}
                    }
                ],
                "transitions": []
            }
        ]
    }
}
