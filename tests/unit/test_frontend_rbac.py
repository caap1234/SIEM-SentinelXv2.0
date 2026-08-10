import pytest
from app.core.rbac import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_OPERATOR,
    ROLE_VIEWER,
    check_role_permission,
    PERM_ALERTS_READ,
    PERM_ALERTS_MANAGE,
    PERM_INCIDENTS_MANAGE,
    PERM_AGENTS_MANAGE,
    PERM_CONFIG_MANAGE,
)


def test_rbac_role_permissions_matrix():
    # Admin has all permissions
    assert check_role_permission(ROLE_ADMIN, PERM_ALERTS_READ) is True
    assert check_role_permission(ROLE_ADMIN, PERM_ALERTS_MANAGE) is True
    assert check_role_permission(ROLE_ADMIN, PERM_AGENTS_MANAGE) is True

    # Analyst has alerts read, manage, incidents manage, but NOT configuration manage
    assert check_role_permission(ROLE_ANALYST, PERM_ALERTS_READ) is True
    assert check_role_permission(ROLE_ANALYST, PERM_ALERTS_MANAGE) is True
    assert check_role_permission(ROLE_ANALYST, PERM_INCIDENTS_MANAGE) is True
    assert check_role_permission(ROLE_ANALYST, PERM_CONFIG_MANAGE) is False

    # Operator has alerts read and incidents manage, but NOT configuration manage
    assert check_role_permission(ROLE_OPERATOR, PERM_ALERTS_READ) is True
    assert check_role_permission(ROLE_OPERATOR, PERM_CONFIG_MANAGE) is False

    # Viewer has ONLY read permissions
    assert check_role_permission(ROLE_VIEWER, PERM_ALERTS_READ) is True
    assert check_role_permission(ROLE_VIEWER, PERM_ALERTS_MANAGE) is False
    assert check_role_permission(ROLE_VIEWER, PERM_AGENTS_MANAGE) is False
