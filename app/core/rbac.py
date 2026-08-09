# app/core/rbac.py
"""
Módulo de Control de Acceso Basado en Roles (RBAC) para SentinelX SIEM.
"""
from __future__ import annotations

from typing import Dict, Set

# Definición de Roles Estándar
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"

# Definición de Permisos Granulares
PERM_INGEST_READ = "ingest.read"
PERM_ALERTS_READ = "alerts.read"
PERM_ALERTS_MANAGE = "alerts.manage"
PERM_INCIDENTS_MANAGE = "incidents.manage"
PERM_AGENTS_MANAGE = "agents.manage"
PERM_CONFIG_MANAGE = "configuration.manage"

# Matriz Estática de Roles y Permisos (Default Policy)
ROLE_PERMISSIONS_MAP: Dict[str, Set[str]] = {
    ROLE_ADMIN: {
        PERM_INGEST_READ,
        PERM_ALERTS_READ,
        PERM_ALERTS_MANAGE,
        PERM_INCIDENTS_MANAGE,
        PERM_AGENTS_MANAGE,
        PERM_CONFIG_MANAGE,
    },
    ROLE_ANALYST: {
        PERM_INGEST_READ,
        PERM_ALERTS_READ,
        PERM_ALERTS_MANAGE,
        PERM_INCIDENTS_MANAGE,
    },
    ROLE_OPERATOR: {
        PERM_INGEST_READ,
        PERM_ALERTS_READ,
        PERM_AGENTS_MANAGE,
    },
    ROLE_VIEWER: {
        PERM_INGEST_READ,
        PERM_ALERTS_READ,
    },
}


def check_role_permission(role_name: str, permission_name: str) -> bool:
    """
    Verifica si un rol posee el permiso especificado.
    """
    role = (role_name or "").lower().strip()
    if role == ROLE_ADMIN:
        return True

    allowed_perms = ROLE_PERMISSIONS_MAP.get(role, set())
    return permission_name in allowed_perms
