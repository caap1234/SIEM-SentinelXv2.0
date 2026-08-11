# app/core/opensearch_client.py
"""
Cliente asíncrono y helpers de conexión con OpenSearch para SentinelX SIEM.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.opensearch_config import (
    OPENSEARCH_URL,
    OPENSEARCH_USER,
    OPENSEARCH_PASSWORD,
    OPENSEARCH_VERIFY_CERTS,
    INDEX_TEMPLATE_NAME,
    INDEX_TEMPLATE_BODY,
    ISM_POLICY_ID,
    ISM_POLICY_BODY,
)
from app.schemas.normalized_event import NormalizedEvent

logger = logging.getLogger("sentinelx.opensearch")

try:
    from opensearchpy import OpenSearch, helpers
    HAS_OPENSEARCH = True
except ImportError:
    HAS_OPENSEARCH = False


class OpenSearchServiceError(Exception):
    """Excepción base para errores de OpenSearch."""
    pass


class OpenSearchUnavailableError(OpenSearchServiceError):
    """Se lanza cuando el clúster de OpenSearch no está disponible."""
    pass


class OpenSearchClient:
    _instance: Optional[OpenSearchClient] = None

    def __init__(self, url: str = OPENSEARCH_URL) -> None:
        self.url = url
        self.client: Any = None
        self._connected = False

    @classmethod
    def get_instance(cls) -> OpenSearchClient:
        if cls._instance is None:
            cls._instance = OpenSearchClient()
        return cls._instance

    def connect(self) -> bool:
        """Inicializa la conexión síncrona/asíncrona con OpenSearch."""
        if not HAS_OPENSEARCH:
            logger.warning("opensearch-py no instalado; operando en modo offline/mock.")
            return False

        if self._connected and self.client:
            return True

        try:
            auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD) if OPENSEARCH_USER else None
            self.client = OpenSearch(
                hosts=[self.url],
                http_auth=auth,
                verify_certs=OPENSEARCH_VERIFY_CERTS,
                ssl_show_warn=False,
                timeout=5,
                max_retries=3,
                retry_on_timeout=True,
            )
            if self.client.ping():
                self._connected = True
                logger.info("Conexión exitosa con OpenSearch en %s", self.url)
                self.ensure_index_templates_and_ism()
                return True
            else:
                self._connected = False
                logger.warning("Ping fallido hacia OpenSearch en %s", self.url)
                return False
        except Exception as e:
            self._connected = False
            logger.warning("No se pudo conectar a OpenSearch en %s: %s", self.url, e)
            return False

    def ensure_index_templates_and_ism(self) -> None:
        """Crea la política ISM y el Index Template con Data Stream si no existen."""
        if not self.client:
            return

        try:
            # 1. ISM Policy
            try:
                self.client.transport.perform_request(
                    "PUT",
                    f"/_plugins/_ism/policies/{ISM_POLICY_ID}",
                    body=ISM_POLICY_BODY,
                )
                logger.info("Política ISM %s verificada/creada", ISM_POLICY_ID)
            except Exception as e:
                logger.debug("Politica ISM ya existente o error menor: %s", e)

            # 2. Index Template
            try:
                self.client.indices.put_index_template(
                    name=INDEX_TEMPLATE_NAME,
                    body=INDEX_TEMPLATE_BODY,
                )
                logger.info("Index Template %s verificado/creado", INDEX_TEMPLATE_NAME)
            except Exception as e:
                logger.warning("Error al crear Index Template %s: %s", INDEX_TEMPLATE_NAME, e)

        except Exception as e:
            logger.error("Fallo durante la inicialización de plantillas de OpenSearch: %s", e)

    def bulk_index_events(
        self,
        events: List[NormalizedEvent],
        target_stream: str = "sentinelx-events-hosting-default",
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Indexa una lista de eventos canónicos `NormalizedEvent` en un Data Stream de OpenSearch.
        Retorna (exitosos_count, lista_errores).
        """
        if not self._connected or not self.client:
            if not self.connect():
                raise OpenSearchUnavailableError("Clúster OpenSearch fuera de línea")

        actions = []
        for ev in events:
            doc = ev.to_opensearch_doc()
            actions.append(
                {
                    "_op_type": "create",  # Requerido por Data Streams
                    "_index": target_stream,
                    "_id": str(ev.event.id),
                    "_source": doc,
                }
            )

        try:
            success_count, errors = helpers.bulk(
                self.client,
                actions,
                stats_only=False,
                raise_on_error=False,
            )
            failed_items = [err for err in errors if isinstance(err, dict)]
            return success_count, failed_items
        except Exception as e:
            logger.error("Error catastrófico en bulk index de OpenSearch: %s", e)
            raise OpenSearchServiceError(f"Error en indexación por lotes: {e}") from e

    def search_events(
        self,
        query_body: Dict[str, Any],
        tenant_id: str,
        target_stream: str = "sentinelx-events-*",
    ) -> Dict[str, Any]:

        """
        Ejecuta una búsqueda en OpenSearch garantizando el aislamiento estricto por tenant_id.
        Inyecta obligatoriamente el filtro term: tenant.id.
        """
        if not self._connected or not self.client:
            if not self.connect():
                raise OpenSearchUnavailableError("Clúster OpenSearch fuera de línea")

        # Inyectar filtro obligatorio de tenant
        tenant_filter = {"term": {"tenant.id": tenant_id}}

        if "query" not in query_body:
            query_body["query"] = {"bool": {"filter": [tenant_filter]}}
        elif "bool" not in query_body["query"]:
            orig_q = query_body["query"]
            query_body["query"] = {"bool": {"must": [orig_q], "filter": [tenant_filter]}}
        else:
            filters = query_body["query"]["bool"].get("filter", [])
            if isinstance(filters, list):
                filters.append(tenant_filter)
            else:
                query_body["query"]["bool"]["filter"] = [filters, tenant_filter]

        if "track_total_hits" not in query_body:
            query_body["track_total_hits"] = True

        try:
            res = self.client.search(index=target_stream, body=query_body)
            return res
        except Exception as e:
            logger.error("Error en búsqueda de OpenSearch para tenant %s: %s", tenant_id, e)
            raise OpenSearchServiceError(f"Error en búsqueda: {e}") from e

