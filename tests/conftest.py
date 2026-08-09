import os
import sys

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-testing-only-123456789")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    """Integration test client that does NOT require a live DB (uses app directly)."""
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
