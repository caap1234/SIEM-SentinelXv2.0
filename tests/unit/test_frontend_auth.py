import base64
import json
import pytest

from app.core.security import create_access_token


def test_jwt_structure_decodable():
    # Verify that JWTs created by backend contain tenant_id, role, sub
    token = create_access_token(data={"sub": "1", "role": "admin", "tenant_id": "tenant-acme"})
    parts = token.split(".")
    assert len(parts) == 3

    # Decode payload part
    payload_b64 = parts[1] + "=="
    payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
    payload = json.loads(payload_json)

    assert payload["sub"] == "1"
    assert payload["role"] == "admin"
    assert payload["tenant_id"] == "tenant-acme"
