import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models.tenant import Tenant
from app.models.agent_api_key import AgentApiKey
from app.services.agent_api_key_service import (
    create_agent_api_key,
    validate_agent_api_key,
    revoke_agent_api_key,
)

engine = create_engine("sqlite:///:memory:")
Tenant.__table__.create(bind=engine, checkfirst=True)
AgentApiKey.__table__.create(bind=engine, checkfirst=True)
SessionLocal = sessionmaker(bind=engine)


def test_agent_api_key_lifecycle():
    db = SessionLocal()

    # 1. Create agent key
    raw_key, record = create_agent_api_key(db, name="srv-cpanel-key", tenant_id="tenant-acme")
    assert raw_key.startswith("sx_live_")
    assert record.tenant_id == "tenant-acme"
    assert record.status == "active"

    # 2. Validate active key
    val_rec = validate_agent_api_key(db, raw_key)
    assert val_rec is not None
    assert val_rec.tenant_id == "tenant-acme"
    assert val_rec.last_used_at is not None

    # 3. Validate invalid key -> None
    assert validate_agent_api_key(db, "sx_live_invalid_key_12345") is None

    # 4. Revoke key
    revoked = revoke_agent_api_key(db, str(record.id))
    assert revoked is True

    # 5. Validate revoked key -> None
    assert validate_agent_api_key(db, raw_key) is None

    db.close()
