"""
Tests para el router de Agentes Linux (/api/v1/agents).
Usa una base de datos SQLite en memoria con StaticPool para
garantizar que create_all y las queries usen la misma conexión.
"""
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.db import Base, get_db

# Importar todos los modelos para que Base.metadata los conozca
import app.models.agent  # noqa: F401
import app.models.event  # noqa: F401
import app.models.tenant  # noqa: F401
import app.models.user  # noqa: F401
import app.models.alert  # noqa: F401
import app.models.rule_v2  # noqa: F401
import app.models.job_state  # noqa: F401

from app.main import app

# Engine SQLite en memoria con StaticPool (misma conexión siempre)
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

# Habilitar foreign keys en SQLite
@event.listens_for(TEST_ENGINE, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

TestSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=TEST_ENGINE
)

HEADERS = {"X-API-Key": "test-api-key"}


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True, scope="module")
def setup_db():
    """Crea todas las tablas y seed del tenant 'default'."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    # Seed del tenant 'default' requerido por FK en registered_agents
    from app.models.tenant import Tenant
    db = TestSessionLocal()
    if not db.query(Tenant).filter_by(id="default").first():
        db.add(Tenant(id="default", name="Default Tenant", status="active"))
        db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


client = TestClient(app)


def test_list_agents_endpoint():
    res = client.get("/api/v1/agents", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "agents" in data
    assert "summary" in data
    assert data["tenant_id"] == "default"


def test_agent_heartbeat_endpoint():
    payload = {
        "hostname": "srv-cpanel-test-01",
        "ip_address": "192.168.1.50",
        "os_info": "AlmaLinux 9.4",
        "kernel": "5.14.0-427.el9.x86_64",
        "agent_version": "1.0.0",
        "metadata_json": {"cpu_cores": 8, "ram_gb": 32},
    }
    res = client.post("/api/v1/agents/heartbeat", json=payload, headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["status"] == "healthy"


def test_get_agent_detail_not_found():
    res = client.get("/api/v1/agents/non-existent-host", headers=HEADERS)
    assert res.status_code == 404
