# app/core/bootstrap_rules_v2.py
from __future__ import annotations

import json
import os
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.models.rule_v2 import RuleV2


DEFAULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # app/
    "seed",
    "rules_v2_defaults.json",
)


def seed_default_rules_v2(db: Session) -> None:
    insp = inspect(db.get_bind())
    if not insp.has_table("rules_v2"):
        return

    if not os.path.exists(DEFAULTS_PATH):
        return

    with open(DEFAULTS_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)

    if not isinstance(items, list) or not items:
        return

    existing_rules = {r.name: r for r in db.query(RuleV2).all()}

    for r in items:
        if not isinstance(r, dict):
            continue
        name = r.get("name")
        if not name or not r.get("source") or not r.get("event_type"):
            continue

        if name in existing_rules:
            obj = existing_rules[name]
            obj.source = r.get("source")
            obj.group_by = r.get("group_by")
            obj.match = r.get("match")
            obj.condition = r.get("condition")
            obj.window_seconds = r.get("window_seconds")
            obj.severity = r.get("severity")
        else:
            db.add(RuleV2(**r))

    db.commit()
