# app/services/security_list_service.py
from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.security_list import (
    SecurityListAudit,
    SecurityListEntry,
    SecurityListIgnoreLog,
)

logger = logging.getLogger("sentinelx.security_lists")


@dataclass(frozen=True)
class IgnoreList:
    ips: Set[str]
    cidrs: Tuple[ipaddress._BaseNetwork, ...]  # type: ignore[attr-defined]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ip_in_cidrs(ip: Optional[str], cidrs: List[str]) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for c in cidrs:
        c = (c or "").strip()
        if not c:
            continue
        try:
            if "/" in c:
                net = ipaddress.ip_network(c, strict=False)
                if ip_obj in net:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(c):
                    return True
        except ValueError:
            continue
    return False


def _is_non_global_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        return not bool(obj.is_global)
    except Exception:
        return bool(
            getattr(obj, "is_private", False)
            or getattr(obj, "is_loopback", False)
            or getattr(obj, "is_link_local", False)
            or getattr(obj, "is_reserved", False)
            or getattr(obj, "is_unspecified", False)
        )


class SecurityListService:
    """
    Servicio centralizado de Listas de Seguridad con soporte de caché en memoria TTL,
    auditoría, trazabilidad y fallback transparente a JSON.
    """

    _instance: Optional[SecurityListService] = None

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._last_load: Optional[datetime] = None
        self._cache_entries: List[Dict[str, Any]] = []

        # JSON fallback config paths
        self.config_dir = Path(__file__).resolve().parents[1] / "config"
        self.trust_json_path = self.config_dir / "trust_list.json"
        self.blm_ignore_path = self.config_dir / "blacklistmaster_ignore.json"
        self.blm_shared_path = self.config_dir / "blacklistmaster_shared.json"
        self.blm_pmg_path = self.config_dir / "blacklistmaster_pmg.json"

    @classmethod
    def get_instance(cls) -> SecurityListService:
        if cls._instance is None:
            cls._instance = SecurityListService()
        return cls._instance

    def refresh_cache(self, db: Optional[Session] = None) -> None:
        """Forzar recarga del caché desde PostgreSQL (o fallback JSON)."""
        close_session = False
        if db is None:
            db = SessionLocal()
            close_session = True

        try:
            now = _utc_now()
            entries = (
                db.query(SecurityListEntry)
                .filter(SecurityListEntry.enabled.is_(True))
                .filter(
                    or_(
                        SecurityListEntry.expires_at.is_(None),
                        SecurityListEntry.expires_at > now,
                    )
                )
                .all()
            )
            self._cache_entries = [e.to_dict() for e in entries]
            self._last_load = now
            logger.info(f"Caché de listas de seguridad cargado con {len(self._cache_entries)} entradas activas.")
        except Exception as err:
            logger.warning(f"Error al cargar listas de seguridad desde PostgreSQL ({err}). Usando fallback JSON.")
            self._cache_entries = self._load_fallback_entries()
            self._last_load = now
        finally:
            if close_session:
                db.close()

    def _ensure_cache(self, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        now = _utc_now()
        if (
            self._last_load is None
            or (now - self._last_load).total_seconds() >= self.ttl_seconds
        ):
            self.refresh_cache(db)
        return self._cache_entries

    def _load_fallback_entries(self) -> List[Dict[str, Any]]:
        """Construye lista de entradas sintéticas leyendo los archivos JSON estáticos."""
        entries: List[Dict[str, Any]] = []

        # 1. trust_list.json
        if self.trust_json_path.exists():
            try:
                data = json.loads(self.trust_json_path.read_text(encoding="utf-8"))
                for ip in data.get("trusted_ips", []):
                    entries.append({
                        "tenant_id": "global", "list_type": "whitelist_ip",
                        "value": str(ip).strip(), "value_type": "ip",
                        "enabled": True, "expires_at": None, "reason": "Fallback JSON trust_list"
                    })
                for country in data.get("trusted_countries", []):
                    entries.append({
                        "tenant_id": "global", "list_type": "trusted_country",
                        "value": str(country).strip().upper(), "value_type": "country_code",
                        "enabled": True, "expires_at": None, "reason": "Fallback JSON trust_list"
                    })
                for asn in data.get("trusted_asn_numbers", []):
                    entries.append({
                        "tenant_id": "global", "list_type": "trusted_asn",
                        "value": str(asn).strip(), "value_type": "asn",
                        "enabled": True, "expires_at": None, "reason": "Fallback JSON trust_list"
                    })
                servers = data.get("servers", {})
                if isinstance(servers, dict):
                    for srv_name, srv_data in servers.items():
                        if isinstance(srv_data, dict):
                            for ip in srv_data.get("server_ips", []):
                                entries.append({
                                    "tenant_id": "global", "list_type": "trusted_server",
                                    "value": str(ip).strip(), "value_type": "ip",
                                    "list_name": str(srv_name),
                                    "enabled": True, "expires_at": None, "reason": "Fallback JSON trust_list"
                                })
                lists = data.get("lists", {})
                if isinstance(lists, dict):
                    for lname, litems in lists.items():
                        if isinstance(litems, list):
                            for item in litems:
                                entries.append({
                                    "tenant_id": "global", "list_type": "list_ref",
                                    "value": str(item).strip(), "value_type": "token",
                                    "list_name": str(lname),
                                    "enabled": True, "expires_at": None, "reason": "Fallback JSON trust_list"
                                })
            except Exception as e:
                logger.error(f"Error al leer fallback trust_list.json: {e}")

        # 2. blacklistmaster_ignore.json
        if self.blm_ignore_path.exists():
            try:
                data = json.loads(self.blm_ignore_path.read_text(encoding="utf-8"))
                for ip in data.get("ips", []):
                    entries.append({
                        "tenant_id": "global", "list_type": "blm_ignore",
                        "value": str(ip).strip(), "value_type": "ip",
                        "enabled": True, "expires_at": None, "reason": "Fallback JSON blm_ignore"
                    })
                for cidr in data.get("cidrs", []):
                    entries.append({
                        "tenant_id": "global", "list_type": "blm_ignore",
                        "value": str(cidr).strip(), "value_type": "cidr",
                        "enabled": True, "expires_at": None, "reason": "Fallback JSON blm_ignore"
                    })
            except Exception as e:
                logger.error(f"Error al leer fallback blm_ignore: {e}")

        # 3. blacklistmaster_shared.json
        if self.blm_shared_path.exists():
            try:
                data = json.loads(self.blm_shared_path.read_text(encoding="utf-8"))
                servers = data.get("servers", {})
                if isinstance(servers, dict):
                    for srv, payload in servers.items():
                        if isinstance(payload, dict):
                            for ip in payload.get("server_ips", []):
                                entries.append({
                                    "tenant_id": "global", "list_type": "blm_shared",
                                    "value": str(ip).strip(), "value_type": "ip",
                                    "list_name": str(srv),
                                    "enabled": True, "expires_at": None, "reason": "Fallback JSON blm_shared"
                                })
            except Exception as e:
                logger.error(f"Error al leer fallback blm_shared: {e}")

        # 4. blacklistmaster_pmg.json
        if self.blm_pmg_path.exists():
            try:
                data = json.loads(self.blm_pmg_path.read_text(encoding="utf-8"))
                servers = data.get("servers", {})
                if isinstance(servers, dict):
                    for srv, payload in servers.items():
                        if isinstance(payload, dict):
                            for ip in payload.get("server_ips", []):
                                entries.append({
                                    "tenant_id": "global", "list_type": "blm_pmg",
                                    "value": str(ip).strip(), "value_type": "ip",
                                    "list_name": str(srv),
                                    "enabled": True, "expires_at": None, "reason": "Fallback JSON blm_pmg"
                                })
            except Exception as e:
                logger.error(f"Error al leer fallback blm_pmg: {e}")

        return entries

    # =========================================================================
    # CONSULTAS DE DETECCIÓN Y ENGINE (RuleEngineV2 & BlacklistMaster)
    # =========================================================================

    def is_trusted_event_for_rule(
        self,
        *,
        event: Dict[str, Any],
        geo_country: Optional[str],
        rule_emit: Any,
        rule_code: Optional[str] = None,
        tenant_id: str = "global",
        db: Optional[Session] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Evalúa si un evento debe ser ignorado por reglas de confianza.
        Jerarquía de precedencia:
          1. Excepción por regla (rule_code)
          2. Whitelist específica del tenant
          3. Whitelist Global ('global')
          4. IP Privada / Non-Global IP

        Retorna: (is_trusted: bool, ignore_reason: Optional[str], value_matched: Optional[str])
        """
        entries = self._ensure_cache(db)

        ip_client = str(event.get("ip_client") or "").strip() or None
        server = str(event.get("server") or "").strip() or None
        username = str(event.get("username") or "").strip().lower() or None
        extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}
        asn_val = extra.get("asn", {}).get("number") if isinstance(extra.get("asn"), dict) else extra.get("asn_number")
        asn_num = None
        if asn_val is not None:
            try:
                asn_num = int(str(asn_val).strip())
            except Exception:
                pass

        # 1. Chequeo de IP no global (loopback, RFC1918)
        if _is_non_global_ip(ip_client):
            return True, "non_global_ip", ip_client

        # Filtrar entradas activas para este tenant o globales
        active_entries = [
            e for e in entries
            if e.get("enabled", True) and e.get("tenant_id") in (tenant_id, "global")
        ]

        # A. EXCEPCIÓN ESPECÍFICA POR REGLA
        if rule_code:
            rule_exceptions = [e for e in active_entries if e.get("list_type") == "exception_rule" and e.get("rule_code") == rule_code]
            for exc in rule_exceptions:
                val = str(exc.get("value", "")).strip()
                vtype = exc.get("value_type", "ip")
                if vtype in ("ip", "cidr") and ip_client and _ip_in_cidrs(ip_client, [val]):
                    return True, "rule_exception", f"rule:{rule_code}|ip:{val}"
                elif vtype == "country_code" and geo_country and geo_country.upper() == val.upper():
                    return True, "rule_exception", f"rule:{rule_code}|country:{val}"
                elif vtype == "username" and username and username == val.lower():
                    return True, "rule_exception", f"rule:{rule_code}|user:{val}"
                elif vtype == "asn" and asn_num is not None and str(asn_num) == val:
                    return True, "rule_exception", f"rule:{rule_code}|asn:{val}"

        # También verificar rule_emit.trusted_ips_extra, trusted_countries_extra, etc. (Legacy per-rule emit override)
        if isinstance(rule_emit, dict):
            extra_ips = [str(x).strip() for x in rule_emit.get("trusted_ips_extra", []) if str(x).strip()]
            if ip_client and _ip_in_cidrs(ip_client, extra_ips):
                return True, "rule_emit_extra_ip", ip_client

            extra_countries = [str(x).strip().upper() for x in rule_emit.get("trusted_countries_extra", []) if str(x).strip()]
            if geo_country and geo_country.upper() in extra_countries:
                return True, "rule_emit_extra_country", geo_country

            extra_users = [str(x).strip().lower() for x in rule_emit.get("trusted_usernames_extra", []) if str(x).strip()]
            if username and username in extra_users:
                return True, "rule_emit_extra_user", username

        # B. WHITELIST POR TENANT / GLOBAL
        # 1) Países confiables
        trusted_countries = [e["value"].upper() for e in active_entries if e.get("list_type") == "trusted_country"]
        if geo_country and geo_country.upper() in trusted_countries:
            return True, "trusted_country", geo_country

        # 2) ASN confiables
        trusted_asns = [e["value"] for e in active_entries if e.get("list_type") == "trusted_asn"]
        if asn_num is not None and str(asn_num) in trusted_asns:
            return True, "trusted_asn", str(asn_num)

        # 3) IPs y CIDRs confiables (whitelist_ip, whitelist_cidr, trusted_server)
        trusted_cidrs = [
            e["value"] for e in active_entries
            if e.get("list_type") in ("whitelist_ip", "whitelist_cidr", "trusted_server")
        ]
        if ip_client and _ip_in_cidrs(ip_client, trusted_cidrs):
            return True, "trusted_ip", ip_client

        return False, None, None

    def log_ignored_event(
        self,
        *,
        tenant_id: str,
        ignore_reason: str,
        value_matched: str,
        rule_code: Optional[str] = None,
        event_id: Optional[str] = None,
        source: Optional[str] = None,
        server: Optional[str] = None,
        ip_client: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> None:
        """Registra trazabilidad de un evento ignorado en la BD."""
        target_db = db
        close_session = False
        if target_db is None:
            target_db = SessionLocal()
            close_session = True

        try:
            log_entry = SecurityListIgnoreLog(
                tenant_id=tenant_id,
                ignore_reason=ignore_reason,
                value_matched=value_matched,
                rule_code=rule_code,
                event_id=str(event_id) if event_id else None,
                source=source,
                server=server,
                ip_client=ip_client,
                logged_at=_utc_now(),
            )
            target_db.add(log_entry)
            target_db.flush()
            if close_session:
                target_db.commit()
        except Exception as e:
            if close_session:
                target_db.rollback()
            else:
                try:
                    iso_db = SessionLocal()
                    log_entry = SecurityListIgnoreLog(
                        tenant_id=tenant_id,
                        ignore_reason=ignore_reason,
                        value_matched=value_matched,
                        rule_code=rule_code,
                        event_id=str(event_id) if event_id else None,
                        source=source,
                        server=server,
                        ip_client=ip_client,
                        logged_at=_utc_now(),
                    )
                    iso_db.add(log_entry)
                    iso_db.commit()
                    iso_db.close()
                except Exception:
                    pass
            logger.warning(f"No se pudo guardar ignore log: {e}")
        finally:
            if close_session:
                target_db.close()

    def get_list_by_name(
        self, name: str, tenant_id: str = "global", db: Optional[Session] = None
    ) -> List[str]:
        """Recupera lista de valores de referencia (list_ref) por nombre (ej. 'privileged_users')."""
        entries = self._ensure_cache(db)
        out: List[str] = []
        for e in entries:
            if (
                e.get("enabled", True)
                and e.get("tenant_id") in (tenant_id, "global")
                and (
                    (e.get("list_type") == "list_ref" and e.get("list_name") == name)
                    or e.get("list_type") == name
                )
            ):
                v = str(e.get("value", "")).strip()
                if v:
                    out.append(v)
        return out

    def get_blm_ignore_list(
        self, tenant_id: str = "global", db: Optional[Session] = None
    ) -> IgnoreList:
        """Devuelve IgnoreList (ips y cidrs) para el sync de BlacklistMaster."""
        entries = self._ensure_cache(db)
        ips: Set[str] = set()
        cidrs: List[ipaddress._BaseNetwork] = []

        for e in entries:
            if e.get("enabled", True) and e.get("tenant_id") in (tenant_id, "global") and e.get("list_type") == "blm_ignore":
                val = str(e.get("value", "")).strip()
                if not val:
                    continue
                if "/" in val:
                    try:
                        cidrs.append(ipaddress.ip_network(val, strict=False))
                    except Exception:
                        pass
                else:
                    ips.add(val)

        # También incluir ENV por compatibilidad
        for ip_env in (os.getenv("BLACKLISTMASTER_IGNORE_IPS") or "").split(","):
            ip_env = ip_env.strip()
            if ip_env:
                ips.add(ip_env)

        for c_env in (os.getenv("BLACKLISTMASTER_IGNORE_CIDRS") or "").split(","):
            c_env = c_env.strip()
            if c_env:
                try:
                    cidrs.append(ipaddress.ip_network(c_env, strict=False))
                except Exception:
                    pass

        uniq_cidrs = {str(n): n for n in cidrs}
        return IgnoreList(ips=ips, cidrs=tuple(uniq_cidrs.values()))

    def get_blm_inventory_map(
        self, category: str, tenant_id: str = "global", db: Optional[Session] = None
    ) -> Dict[str, str]:
        """Devuelve dict ip -> server_name para 'blm_shared' o 'blm_pmg'."""
        entries = self._ensure_cache(db)
        target_type = f"blm_{category}"  # blm_shared | blm_pmg
        out: Dict[str, str] = {}

        for e in entries:
            if e.get("enabled", True) and e.get("tenant_id") in (tenant_id, "global") and e.get("list_type") == target_type:
                ip_val = str(e.get("value", "")).strip()
                srv_name = str(e.get("list_name", "")).strip() or f"{category}_server"
                if ip_val:
                    out[ip_val] = srv_name

        return out

    # =========================================================================
    # OPERACIONES CRUD CON AUDITORÍA
    # =========================================================================

    def create_entry(
        self,
        db: Session,
        *,
        tenant_id: str = "global",
        list_type: str,
        value: str,
        value_type: str = "ip",
        list_name: Optional[str] = None,
        rule_code: Optional[str] = None,
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        enabled: bool = True,
        created_by: str = "system",
        ip_address: Optional[str] = None,
    ) -> SecurityListEntry:
        entry = SecurityListEntry(
            tenant_id=tenant_id,
            list_type=list_type,
            value=value.strip(),
            value_type=value_type,
            list_name=list_name.strip() if list_name else None,
            rule_code=rule_code.strip() if rule_code else None,
            reason=reason,
            expires_at=expires_at,
            enabled=enabled,
            created_by=created_by,
            created_at=_utc_now(),
        )
        db.add(entry)
        db.flush()

        audit = SecurityListAudit(
            entry_id=entry.id,
            action="create",
            new_value=json.dumps(entry.to_dict(), default=str),
            performed_by=created_by,
            performed_at=_utc_now(),
            ip_address=ip_address,
            reason=reason or "Creación inicial",
        )
        db.add(audit)
        db.commit()

        # Invalidate cache
        self.refresh_cache(db)
        try:
            from app.services.nats_service import NatsService
            NatsService.get_instance().notify_invalidation_sync(
                kind="lists",
                tenant_id=entry.tenant_id,
                list_type=entry.list_type,
                list_name=entry.list_name,
                action="create",
            )
        except Exception:
            pass
        return entry

    def update_entry(
        self,
        db: Session,
        *,
        entry_id: int,
        data: Dict[str, Any],
        updated_by: str = "system",
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> SecurityListEntry:
        entry = db.query(SecurityListEntry).filter(SecurityListEntry.id == entry_id).one_or_none()
        if not entry:
            raise ValueError(f"Entrada con ID {entry_id} no encontrada.")

        old_dict = entry.to_dict()
        changes = []

        for field in ("value", "value_type", "list_name", "rule_code", "reason", "enabled", "expires_at", "tenant_id", "list_type"):
            if field in data:
                new_val = data[field]
                old_val = getattr(entry, field)
                if old_val != new_val:
                    setattr(entry, field, new_val)
                    changes.append(f"{field}: '{old_val}' -> '{new_val}'")

        entry.updated_by = updated_by
        entry.updated_at = _utc_now()
        db.flush()

        audit = SecurityListAudit(
            entry_id=entry.id,
            action="update",
            field_changed=", ".join(changes) if changes else "none",
            old_value=json.dumps(old_dict, default=str),
            new_value=json.dumps(entry.to_dict(), default=str),
            performed_by=updated_by,
            performed_at=_utc_now(),
            ip_address=ip_address,
            reason=reason or "Actualización de registro",
        )
        db.add(audit)
        db.commit()

        self.refresh_cache(db)
        try:
            from app.services.nats_service import NatsService
            NatsService.get_instance().notify_invalidation_sync(
                kind="lists",
                tenant_id=entry.tenant_id,
                list_type=entry.list_type,
                list_name=entry.list_name,
                action="update",
            )
        except Exception:
            pass
        return entry

    def delete_entry(
        self,
        db: Session,
        *,
        entry_id: int,
        performed_by: str = "system",
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        entry = db.query(SecurityListEntry).filter(SecurityListEntry.id == entry_id).one_or_none()
        if not entry:
            return False

        old_dict = entry.to_dict()
        t_id = entry.tenant_id
        l_type = entry.list_type
        l_name = entry.list_name

        audit = SecurityListAudit(
            entry_id=entry.id,
            action="delete",
            old_value=json.dumps(old_dict, default=str),
            performed_by=performed_by,
            performed_at=_utc_now(),
            ip_address=ip_address,
            reason=reason or "Eliminación de registro",
        )
        db.add(audit)
        db.delete(entry)
        db.commit()

        self.refresh_cache(db)
        try:
            from app.services.nats_service import NatsService
            NatsService.get_instance().notify_invalidation_sync(
                kind="lists",
                tenant_id=t_id,
                list_type=l_type,
                list_name=l_name,
                action="delete",
            )
        except Exception:
            pass
        return True

    def toggle_entry(
        self,
        db: Session,
        *,
        entry_id: int,
        enabled: Optional[bool] = None,
        performed_by: str = "system",
        ip_address: Optional[str] = None,
    ) -> SecurityListEntry:
        entry = db.query(SecurityListEntry).filter(SecurityListEntry.id == entry_id).one_or_none()
        if not entry:
            raise ValueError(f"Entrada con ID {entry_id} no encontrada.")

        new_status = not entry.enabled if enabled is None else enabled
        action = "enable" if new_status else "disable"

        old_dict = entry.to_dict()
        entry.enabled = new_status
        entry.updated_by = performed_by
        entry.updated_at = _utc_now()
        db.flush()

        audit = SecurityListAudit(
            entry_id=entry.id,
            action=action,
            field_changed="enabled",
            old_value=json.dumps(old_dict, default=str),
            new_value=json.dumps(entry.to_dict(), default=str),
            performed_by=performed_by,
            performed_at=_utc_now(),
            ip_address=ip_address,
            reason=f"Cambio de estado a {action}",
        )
        db.add(audit)
        db.commit()

        self.refresh_cache(db)
        return entry
