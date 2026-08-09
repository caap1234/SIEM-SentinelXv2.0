import pytest
from unittest.mock import MagicMock, patch

from app.core.opensearch_config import (
    INDEX_TEMPLATE_NAME,
    INDEX_PATTERN,
    ISM_POLICY_ID,
    ECS_COMPONENT_MAPPINGS,
    INDEX_TEMPLATE_BODY,
    ISM_POLICY_BODY,
)
from app.core.opensearch_client import (
    OpenSearchClient,
    OpenSearchUnavailableError,
    OpenSearchServiceError,
)
from app.schemas.normalized_event import NormalizedEvent, EventMeta, TenantMeta, SourceMeta


def test_opensearch_config_ecs_mappings():
    props = ECS_COMPONENT_MAPPINGS["properties"]
    assert props["@timestamp"]["type"] == "date"
    assert props["source"]["properties"]["ip"]["type"] == "ip"
    assert props["destination"]["properties"]["ip"]["type"] == "ip"
    assert props["event"]["properties"]["severity"]["type"] == "integer"
    assert props["event"]["properties"]["risk_score"]["type"] == "float"


def test_opensearch_index_template_structure():
    assert INDEX_TEMPLATE_BODY["index_patterns"] == [INDEX_PATTERN]
    assert "data_stream" in INDEX_TEMPLATE_BODY
    assert INDEX_TEMPLATE_BODY["template"]["settings"]["plugins.index_state_management.policy_id"] == ISM_POLICY_ID


def test_opensearch_ism_policy_states():
    policy = ISM_POLICY_BODY["policy"]
    state_names = [s["name"] for s in policy["states"]]
    assert "hot" in state_names
    assert "warm" in state_names
    assert "delete" in state_names


def test_opensearch_client_offline_raises_error():
    client = OpenSearchClient(url="http://localhost:59999")
    event = NormalizedEvent(
        tenant=TenantMeta(id="tenant-1"),
        source=SourceMeta(ip="1.1.1.1"),
    )

    with pytest.raises(OpenSearchUnavailableError):
        client.bulk_index_events([event])


def test_opensearch_client_bulk_index_success():
    client = OpenSearchClient()
    client._connected = True
    
    mock_os = MagicMock()
    client.client = mock_os

    event = NormalizedEvent(
        tenant=TenantMeta(id="tenant-acme"),
        event=EventMeta(id="evt-100"),
        source=SourceMeta(ip="198.51.100.1"),
    )

    with patch("opensearchpy.helpers.bulk", return_value=(1, [])):
        success_count, errors = client.bulk_index_events([event])

    assert success_count == 1
    assert len(errors) == 0
