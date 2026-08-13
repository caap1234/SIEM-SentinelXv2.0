# app/services/detection_core.py
"""
Núcleo Único y Canónico de Evaluación de Reglas de Detección (Detection Core).
Proporciona la única fuente de verdad para:
- Extracción de campos canónicos ECS v1.0.0
- Mapeo de categorías lógicas de dataset (SSH_AUTH, MAIL_AUTH, WEB_ACCESS, etc.)
- Evaluación de match y operadores de condición
- Mantenimiento de contadores y ventanas deslizantes
- Generación de claves de agrupación (group_key)
- Trazabilidad y observabilidad estructurada (RULE_ENGINE_DEBUG)
"""
from __future__ import annotations

import ast
import ipaddress
import logging
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinelx.detection_core")

# Flag global de depuración activable vía env RULE_ENGINE_DEBUG=true
DEBUG_MODE = os.getenv("RULE_ENGINE_DEBUG", "false").strip().lower() in ("true", "1", "yes")

# Matriz de Categorías Lógicas de Dataset basadas estrictamente en los datasets reales emitidos por los parsers
DATASET_CATEGORIES: Dict[str, Set[str]] = {
    "SSH_AUTH": {"system_secure", "ssh_secure"},
    "MAIL_AUTH": {"maillog_dovecot"},
    "MAIL_FLOW": {"exim_mainlog"},
    "WEB_ACCESS": {"nginx_access", "apache_access", "cpanel_access"},
    "WEB_ERROR": {"apache_error", "wp_error"},
    "WAF": {"modsec"},
    "PANEL": {"cpanel_access", "panel_access", "filemanager"},
    "SYSTEM_METRICS": {"sar", "sar_stats"},
    "SYSTEM_LOGS": {"system", "auditd"},
    "SECURITY_AGENT": {"lfd", "imunify360"},
}

_DATASET_TO_CATEGORY: Dict[str, str] = {}
for cat, datasets in DATASET_CATEGORIES.items():
    for ds in datasets:
        _DATASET_TO_CATEGORY[ds] = cat


def norm_source(v: Optional[str]) -> str:
    if not v:
        return ""
    s = (v or "").strip().lower()
    if s in _DATASET_TO_CATEGORY:
        return _DATASET_TO_CATEGORY[s]
    return s.upper()

_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.In, ast.NotIn,
    ast.Name, ast.Load,
    ast.Constant,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
)

_ALLOWED_NAMES = {"True": True, "False": False, "None": None}


def safe_eval_expr(expr: str, ctx: Dict[str, Any]) -> bool:
    if not expr:
        return True
    try:
        tree = ast.parse(expr, mode="eval")
        for node in ast.walk(tree):
            if not isinstance(node, _ALLOWED_NODES):
                raise ValueError(f"Nodo AST no permitido: {type(node).__name__}")
            if isinstance(node, ast.Name) and node.id not in ctx and node.id not in _ALLOWED_NAMES:
                raise ValueError(f"Variable no permitida en expresión: {node.id}")
        code = compile(tree, "<detection_rule_condition>", "eval")
        return bool(eval(code, {"__builtins__": {}}, {**_ALLOWED_NAMES, **ctx}))
    except Exception as e:
        if DEBUG_MODE:
            logger.debug("Error evaluando condición '%s': %s", expr, e)
        return False


def _as_str(val: Any) -> str:
    if val is None:
        return ""
    try:
        return str(val)
    except Exception:
        return ""


def _ip_subnet(ip: Optional[str], prefix: int = 24) -> Optional[str]:
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if obj.version != 4:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return f"{net.network_address}/{prefix}"
    except Exception:
        return None


def get_raw_field(event: Any, path: str) -> Any:
    if not path or event is None:
        return None
    parts = path.split(".")
    cur: Any = event
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif hasattr(cur, p):
            cur = getattr(cur, p)
        else:
            return None
    return cur


def get_canonical_field(event: Any, path: str) -> Any:
    if not path or event is None:
        return None

    # Subnets calculadas dinámicamente desde el IP canónico source.ip
    if path == "ip_subnet24":
        return _ip_subnet(_as_str(get_canonical_field(event, "source.ip")).strip() or None, 24)
    if path == "ip_subnet16":
        return _ip_subnet(_as_str(get_canonical_field(event, "source.ip")).strip() or None, 16)

    # 1. Extracción primaria canónica ECS
    val = get_raw_field(event, path)
    if val is not None:
        return val

    # 2. Resoluciones de equivalencias ECS primarias
    if path == "source.ip":
        return get_raw_field(event, "ip_client") or get_raw_field(event, "client.ip")

    if path == "user.name":
        return get_raw_field(event, "username")

    if path == "event.outcome":
        o = get_raw_field(event, "outcome") or get_raw_field(event, "extra.action")
        if o in ("fail", "failed", "failure"):
            return "failure"
        if o in ("success", "ok", "passed"):
            return "success"
        return o

    if path == "service.name":
        s = get_raw_field(event, "network.protocol") or get_raw_field(event, "extra.protocol")
        if s is None:
            ds = _as_str(get_raw_field(event, "event.dataset") or get_raw_field(event, "source")).lower()
            if "ssh" in ds or "secure" in ds:
                return "ssh"
            elif "dovecot" in ds or "mail" in ds:
                return "imap"
            elif "exim" in ds:
                return "smtp"
            elif "http" in ds or "nginx" in ds or "apache" in ds or "panel" in ds:
                return "http"
        return s

    if path == "url.path":
        return get_raw_field(event, "url.original") or get_raw_field(event, "extra.http.path") or get_raw_field(event, "extra.request_uri")

    if path == "http.status_code":
        return get_raw_field(event, "http_status") or get_raw_field(event, "status_code") or get_raw_field(event, "extra.status_code")

    if path == "source.geo_country_iso_code":
        return get_raw_field(event, "extra.geo.country_code") or get_raw_field(event, "geo_country") or get_raw_field(event, "country_code")

    if path == "source.as_number":
        return get_raw_field(event, "extra.asn.number") or get_raw_field(event, "asn_number")

    if path == "customer.domain_name":
        return get_raw_field(event, "extra.vhost") or get_raw_field(event, "domain")

    if path == "host.name":
        return get_raw_field(event, "server") or get_raw_field(event, "host.hostname")

    # 3. Capa de compatibilidad legacy aislada para reglas antiguas
    return _get_legacy_field_fallback(event, path)


def _get_legacy_field_fallback(event: Any, path: str) -> Any:
    """Capa explícita de retrocompatibilidad aislada para reglas personalizadas creadas previamente."""
    if path == "extra.action":
        o = get_canonical_field(event, "event.outcome")
        return "fail" if o == "failure" else ("success" if o == "success" else o)
    if path == "extra.protocol":
        return get_canonical_field(event, "service.name")
    if path == "ip_client":
        return get_canonical_field(event, "source.ip")
    if path == "username":
        return get_canonical_field(event, "user.name")
    if path == "server":
        return get_canonical_field(event, "host.name")
    if path in ("extra.http.path", "request_uri"):
        return get_canonical_field(event, "url.path")
    if path == "http_status":
        return get_canonical_field(event, "http.status_code")
    if path == "extra.geo.country_code":
        return get_canonical_field(event, "source.geo_country_iso_code")
    if path == "extra.asn.number":
        return get_canonical_field(event, "source.as_number")
    if path == "extra.vhost":
        return get_canonical_field(event, "customer.domain_name")
    return None


def match_source(rule_source: str, event_dataset: str) -> bool:
    r_src = (rule_source or "").strip().upper()
    e_ds = (event_dataset or "").strip().lower()

    if not r_src or not e_ds:
        return True

    # Coincidencia directa exacta
    if r_src.lower() == e_ds:
        return True

    # Coincidencia por Categoría Lógica
    cats = DATASET_CATEGORIES.get(r_src)
    if cats and e_ds in cats:
        return True

    # Fallbacks de alias canónicos
    if r_src == "SSH_SECURE" and e_ds in ("system_secure", "ssh_secure"):
        return True
    if r_src == "MAILLOG_DOVECOT" and e_ds == "maillog_dovecot":
        return True
    if r_src == "EXIM_MAINLOG" and e_ds == "exim_mainlog":
        return True
    if r_src in ("APACHE_ACCESS", "NGINX_ACCESS") and e_ds in ("nginx_access", "apache_access", "cpanel_access"):
        return True
    if r_src == "SAR_STATS" and e_ds in ("sar", "sar_stats"):
        return True

    return False


def match_clause(event: Any, match_dict: Dict[str, Any]) -> bool:
    if not isinstance(match_dict, dict) or not match_dict:
        return True

    for field, cond in match_dict.items():
        val = get_canonical_field(event, field)

        if isinstance(cond, dict):
            if "exists" in cond:
                want = bool(cond["exists"])
                if want != (val is not None and _as_str(val).strip() != ""):
                    return False

            if "eq" in cond:
                if val != cond["eq"]:
                    return False

            if "contains" in cond:
                needle = _as_str(cond["contains"])
                hay = _as_str(val)
                if needle not in hay:
                    return False

            if "contains_any" in cond:
                arr = cond.get("contains_any")
                if not isinstance(arr, list) or not arr:
                    return False
                hay = _as_str(val)
                if not any((_as_str(x) != "") and (_as_str(x) in hay) for x in arr):
                    return False

            if "in" in cond:
                arr = cond.get("in")
                if not isinstance(arr, list) or not arr:
                    return False
                if isinstance(val, str) and val in arr:
                    pass
                elif val not in arr:
                    return False

            if "not_in" in cond:
                arr = cond.get("not_in")
                if isinstance(arr, list) and val in arr:
                    return False

            for cmp_op in (">=", ">", "<=", "<"):
                if cmp_op in cond:
                    try:
                        fval = float(val)
                        fcmp = float(cond[cmp_op])
                    except Exception:
                        return False
                    if cmp_op == ">=" and not (fval >= fcmp):
                        return False
                    if cmp_op == ">" and not (fval > fcmp):
                        return False
                    if cmp_op == "<=" and not (fval <= fcmp):
                        return False
                    if cmp_op == "<" and not (fval < fcmp):
                        return False
        else:
            if val != cond:
                return False

    return True


def build_group_key(event: Any, group_by: List[str]) -> str:
    parts: List[str] = []
    for f in group_by:
        val = get_canonical_field(event, f)
        parts.append(_as_str(val) if val is not None and _as_str(val) != "" else "-")
    return "|".join(parts)
