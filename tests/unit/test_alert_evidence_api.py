import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.main import app
from app.db import Base, get_db
from app.models.alert import Alert
from app.routers.auth import get_current_user
from datetime import datetime, timezone

# Base de datos en memoria para pruebas
engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="module", autouse=True)
def init_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    # Override FastAPI dependency
    def override_get_db():
        try:
            yield session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()
    app.dependency_overrides.pop(get_db, None)

# Mock user dependency
def mock_get_current_user():
    return {"username": "admin", "tenant_id": "global", "roles": ["admin"]}

@pytest.fixture
def setup_mock_alert(db_session: Session):
    # Override authentication
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Create Alert
    alert = Alert(
        rule_name="WEB-003 | Exploit pattern detected (por IP)",
        rule_id=3,
        severity=15,
        server="svdb057",
        source="WEB_ACCESS",
        event_type="http_access",
        group_key="svdb057|192.168.1.100",
        triggered_at=datetime.now(timezone.utc),
        evidence={
            "event_ids": ["uuid-event-1", "uuid-event-2"],
            "raw_samples": []
        }
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    yield alert
    
    # Cleanup overrides
    app.dependency_overrides.pop(get_current_user, None)

def test_alerts_search_by_rule_name(setup_mock_alert):
    client = TestClient(app)
    # Search by rule_name part
    response = client.get("/alerts?q=Exploit")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert any("Exploit" in item["type"] for item in data["items"])

def test_alerts_search_by_rule_id(setup_mock_alert):
    client = TestClient(app)
    # Search by rule_id
    response = client.get("/alerts?q=3")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert any("WEB-003" in item["type"] or "rule:3" in item["type"] for item in data["items"])

def test_get_alert_detail_with_event_ids(setup_mock_alert):
    client = TestClient(app)
    alert_id = setup_mock_alert.id
    response = client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200
    data = response.json()
    assert "event_ids" in data
    assert data["event_ids"] == ["uuid-event-1", "uuid-event-2"]

def test_get_alert_evidence_clean_response(setup_mock_alert):
    client = TestClient(app)
    alert_id = setup_mock_alert.id
    response = client.get(f"/alerts/{alert_id}/evidence")
    assert response.status_code == 200
    data = response.json()
    assert data["is_synthetic"] is True
    assert data["raw_evidence"] is None
