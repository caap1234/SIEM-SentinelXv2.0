import pytest
from fastapi import HTTPException
from app.schemas.dependencies import AuthContext, require_permission
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, PERM_ALERTS_MANAGE, PERM_CONFIG_MANAGE


def test_require_permission_grants_access_for_authorized_role():
    ctx = AuthContext(username="analyst_user", role=ROLE_ANALYST)
    checker = require_permission(PERM_ALERTS_MANAGE)

    # Calling checker with authorized context returns ctx
    result = checker(ctx=ctx)
    assert result.username == "analyst_user"


def test_require_permission_denies_access_with_403_for_unauthorized_role():
    ctx = AuthContext(username="viewer_user", role=ROLE_VIEWER)
    checker = require_permission(PERM_CONFIG_MANAGE)

    # Calling checker with unauthorized role MUST raise HTTP 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        checker(ctx=ctx)

    assert exc_info.value.status_code == 403
    assert "Permiso denegado" in exc_info.value.detail


def test_require_permission_admin_bypasses_all_checks():
    ctx = AuthContext(username="admin_user", role=ROLE_ADMIN)
    checker = require_permission(PERM_CONFIG_MANAGE)

    result = checker(ctx=ctx)
    assert result.role == ROLE_ADMIN
