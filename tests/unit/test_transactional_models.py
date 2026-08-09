import pytest
from app.models.tenant import Tenant
from app.models.rbac import Role, Permission
from app.models.agent import RegisteredAgent
from app.models.audit_log import AuditLog
from app.core.rbac import (
    check_role_permission,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    PERM_ALERTS_READ,
    PERM_ALERTS_MANAGE,
    PERM_CONFIG_MANAGE,
)


def test_tenant_model_defaults():
    t = Tenant(id="tenant-hosting-1", name="Acme Hosting")
    assert t.id == "tenant-hosting-1"
    assert t.name == "Acme Hosting"
    assert t.status == "active" or t.status is None


def test_rbac_permissions_check():
    # Admin has all permissions
    assert check_role_permission(ROLE_ADMIN, PERM_CONFIG_MANAGE) is True
    assert check_role_permission(ROLE_ADMIN, PERM_ALERTS_MANAGE) is True

    # Analyst has alert manage but NOT config manage
    assert check_role_permission(ROLE_ANALYST, PERM_ALERTS_MANAGE) is True
    assert check_role_permission(ROLE_ANALYST, PERM_CONFIG_MANAGE) is False

    # Viewer has read permissions only
    assert check_role_permission(ROLE_VIEWER, PERM_ALERTS_READ) is True
    assert check_role_permission(ROLE_VIEWER, PERM_ALERTS_MANAGE) is False


def test_registered_agent_model_defaults():
    agent = RegisteredAgent(
        hostname="srv-cpanel-10.acme.com",
        ip_address="198.51.100.10",
        os_info="AlmaLinux 9.4",
        agent_version="1.0.0",
    )
    assert agent.hostname == "srv-cpanel-10.acme.com"
    assert agent.tenant_id == "default" or agent.tenant_id is None


def test_audit_log_model():
    audit = AuditLog(
        tenant_id="tenant-acme",
        username="admin_user",
        action="create_rule",
        resource="rule:exim_bruteforce",
        status="success",
    )
    assert audit.username == "admin_user"
    assert audit.action == "create_rule"
    assert audit.tenant_id == "tenant-acme"
