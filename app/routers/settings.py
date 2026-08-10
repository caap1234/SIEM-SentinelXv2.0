from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user_setting import UserSetting
from app.routers.auth import get_current_user  # type: ignore

router = APIRouter(prefix="/settings", tags=["Settings"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_user_setting(db: Session, *, user_id: int, key: str) -> Optional[UserSetting]:
    return (
        db.query(UserSetting)
        .filter(UserSetting.user_id == int(user_id), UserSetting.key == key)
        .first()
    )


def _defaults_alert_email() -> Dict[str, Any]:
    return {"high": True, "medium": True, "low": True, "to_email": None}


class AlertEmailSetting(BaseModel):
    high: bool = True
    medium: bool = True
    low: bool = True
    to_email: Optional[str] = Field(default=None, max_length=255)


@router.get("/alert-email", response_model=AlertEmailSetting)
def get_alert_email_setting(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AlertEmailSetting:
    uid = int(getattr(current_user, "id"))
    row = _get_user_setting(db, user_id=uid, key="alert_email")

    if not row or not (row.value or "").strip():
        return AlertEmailSetting(**_defaults_alert_email())

    try:
        data = json.loads(row.value)
        if not isinstance(data, dict):
            raise ValueError("not dict")
    except Exception:
        # si quedó basura en DB, regresamos default sin reventar
        return AlertEmailSetting(**_defaults_alert_email())

    out = _defaults_alert_email()
    out["high"] = bool(data.get("high", True))
    out["medium"] = bool(data.get("medium", True))
    out["low"] = bool(data.get("low", True))
    out["to_email"] = (str(data.get("to_email")).strip() if data.get("to_email") else None)

    return AlertEmailSetting(**out)


@router.put("/alert-email", response_model=AlertEmailSetting)
def put_alert_email_setting(
    payload: AlertEmailSetting,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AlertEmailSetting:
    uid = int(getattr(current_user, "id"))

    to_email = payload.to_email.strip() if payload.to_email else None
    if to_email and not EMAIL_RE.match(to_email):
        raise HTTPException(status_code=422, detail="Invalid to_email")

    data: Dict[str, Any] = {
        "high": bool(payload.high),
        "medium": bool(payload.medium),
        "low": bool(payload.low),
        "to_email": to_email,
    }

    row = _get_user_setting(db, user_id=uid, key="alert_email")
    if not row:
        row = UserSetting(user_id=uid, key="alert_email", value=json.dumps(data))
    else:
        row.value = json.dumps(data)
    row.updated_at = _utc_now()

    db.add(row)
    db.commit()
    db.refresh(row)

    return AlertEmailSetting(**data)


class UserPrefsSetting(BaseModel):
    refresh_interval: str = "30s"
    default_range: str = "24h"
    compact_mode: bool = False


@router.get("", response_model=UserPrefsSetting)
def get_user_prefs_setting(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> UserPrefsSetting:
    uid = int(getattr(current_user, "id"))
    row = _get_user_setting(db, user_id=uid, key="user_prefs")
    if not row or not (row.value or "").strip():
        return UserPrefsSetting()
    try:
        data = json.loads(row.value)
        if isinstance(data, dict):
            return UserPrefsSetting(
                refresh_interval=str(data.get("refresh_interval", "30s")),
                default_range=str(data.get("default_range", "24h")),
                compact_mode=bool(data.get("compact_mode", False)),
            )
    except Exception:
        pass
    return UserPrefsSetting()


@router.put("", response_model=UserPrefsSetting)
def put_user_prefs_setting(
    payload: UserPrefsSetting,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> UserPrefsSetting:
    uid = int(getattr(current_user, "id"))
    data = {
        "refresh_interval": payload.refresh_interval,
        "default_range": payload.default_range,
        "compact_mode": payload.compact_mode,
    }
    row = _get_user_setting(db, user_id=uid, key="user_prefs")
    if not row:
        row = UserSetting(user_id=uid, key="user_prefs", value=json.dumps(data))
    else:
        row.value = json.dumps(data)
    row.updated_at = _utc_now()
    db.add(row)
    db.commit()
    return UserPrefsSetting(**data)


# -----------------------------
# RETENTION POLICY ENDPOINTS
# -----------------------------

from app.services.retention_service import (
    RetentionPolicyConfig,
    RetentionPurgeSummary,
    get_retention_config,
    save_retention_config,
    preview_retention_purge,
    execute_retention_purge,
)


@router.get("/retention", response_model=RetentionPolicyConfig)
def get_retention_policy_endpoint(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> RetentionPolicyConfig:
    return get_retention_config(db)


@router.put("/retention", response_model=RetentionPolicyConfig)
def update_retention_policy_endpoint(
    payload: RetentionPolicyConfig,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> RetentionPolicyConfig:
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required to modify retention policy")
    return save_retention_config(db, payload)


@router.post("/retention/preview", response_model=RetentionPurgeSummary)
def preview_retention_purge_endpoint(
    payload: Optional[RetentionPolicyConfig] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> RetentionPurgeSummary:
    return preview_retention_purge(db, payload)


@router.post("/retention/execute", response_model=RetentionPurgeSummary)
def execute_retention_purge_endpoint(
    payload: Optional[RetentionPolicyConfig] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> RetentionPurgeSummary:
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required to execute retention purge")
    return execute_retention_purge(db, payload)


