import pytest
from unittest.mock import MagicMock, patch

from app.schemas.dependencies import AuthContext
from app.core.opensearch_client import OpenSearchClient
from app.services.evidence_service import EvidenceService, EvidenceAccessDeniedError


def test_auth_context_tenant_resolution():
    ctx = AuthContext(username="user1", tenant_id="tenant-acme", role="analyst")
    assert ctx.tenant_id == "tenant-acme"
    assert ctx.username == "user1"
    assert ctx.has_permission("alerts.read") is True
    assert ctx.has_permission("configuration.manage") is False


def test_opensearch_search_events_injects_tenant_filter():
    client = OpenSearchClient()
    client._connected = True
    mock_os = MagicMock()
    client.client = mock_os

    query = {"query": {"match_all": {}}}
    client.search_events(query_body=query, tenant_id="tenant-hosting")

    # Verify search was called and tenant.id term filter was injected
    mock_os.search.assert_called_once()
    call_args = mock_os.search.call_args[1]
    body = call_args["body"]
    assert "bool" in body["query"]
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"tenant.id": "tenant-hosting"}} in filters


def test_evidence_service_tenant_ownership_enforcement():
    service = EvidenceService()

    # Accessing own tenant evidence key should succeed (mocking underlying download)
    with patch.object(service, "retrieve_and_verify_evidence", return_value=(b"data", {"sha256": "abc"}, True)):
        data, meta, valid = service.retrieve_and_verify_evidence_for_tenant(
            object_key="tenant-acme/2026/08/09/exim/evt1.json.gz",
            tenant_id="tenant-acme",
        )
        assert valid is True

    # Accessing OTHER tenant evidence key MUST raise EvidenceAccessDeniedError
    with pytest.raises(EvidenceAccessDeniedError):
        service.retrieve_and_verify_evidence_for_tenant(
            object_key="tenant-VICTIM/2026/08/09/exim/evt1.json.gz",
            tenant_id="tenant-ATTACKER",
        )
