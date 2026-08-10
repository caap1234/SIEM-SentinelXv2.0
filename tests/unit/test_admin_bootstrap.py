# tests/unit/test_admin_bootstrap.py
"""
Test Unitario para Verificar que el Bootstrap Inicial de Usuario Administrador
Asigna is_admin=True, Rol Admin y Permisos Totales RBAC.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base

from app.models.user import User
from app.models.tenant import Tenant
from app.core.bootstrap import seed_admin_user
from app.schemas.dependencies import AuthContext, ROLE_ADMIN
from app.core.security import create_access_token


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()

    # Seed default tenant
    tenant = Tenant(id="default", name="Default Tenant", status="active")
    session.add(tenant)
    session.commit()

    yield session
    session.close()


def test_seed_admin_user_creates_full_admin(db_session):
    admin_email = "admin@sentinelx.local"
    admin_pass = "SentinelX_Admin_2026!"
    full_name = "SentinelX Admin"

    # 1. Ejecutar bootstrap seed
    seed_admin_user(db=db_session, email=admin_email, password=admin_pass, full_name=full_name)

    # 2. Verificar que existe en la DB con is_admin=True
    user = db_session.query(User).filter(User.email == admin_email).first()
    assert user is not None
    assert user.email == admin_email
    assert user.is_active is True
    assert user.is_admin is True

    # 3. Simular contexto de autenticación AuthContext
    token = create_access_token(data={"sub": str(user.id)})
    assert token is not None

    # Rol resuelto para admin
    user_role = ROLE_ADMIN if user.is_admin else "viewer"
    ctx = AuthContext(
        user_id=user.id,
        username=user.email,
        tenant_id="default",
        role=user_role,
        auth_type="jwt",
    )

    assert ctx.role == "admin"
    assert ctx.has_permission("configuration.manage") is True
    assert ctx.has_permission("agents.manage") is True
    assert ctx.has_permission("incidents.manage") is True
    assert ctx.has_permission("alerts.read") is True
