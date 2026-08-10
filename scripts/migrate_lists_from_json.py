#!/usr/bin/env python3
"""
scripts/migrate_lists_from_json.py

Script para migrar las listas de seguridad estáticas JSON existentes en app/config/
hacia la base de datos PostgreSQL (tabla security_list_entries).

Permite ejecutar la migración inicial manteniendo la compatibilidad.
"""

import json
import os
import sys
from pathlib import Path

# Añadir directorio raíz al path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import Base, SessionLocal, engine
from app.models.security_list import SecurityListEntry, SecurityListAudit
from app.services.security_list_service import SecurityListService


def migrate():
    print("=== Migración de Listas JSON a PostgreSQL (security_list_entries) ===")

    # Asegurar que las tablas existan
    Base.metadata.create_all(bind=engine)

    config_dir = Path(__file__).resolve().parents[1] / "app" / "config"
    trust_json = config_dir / "trust_list.json"
    blm_ignore_json = config_dir / "blacklistmaster_ignore.json"
    blm_shared_json = config_dir / "blacklistmaster_shared.json"
    blm_pmg_json = config_dir / "blacklistmaster_pmg.json"

    inserted_cnt = 0
    skipped_cnt = 0

    with SessionLocal() as db:
        def _add_entry(
            tenant_id: str,
            list_type: str,
            value: str,
            value_type: str,
            list_name: str = None,
            rule_code: str = None,
            reason: str = "Migración inicial desde JSON",
        ):
            nonlocal inserted_cnt, skipped_cnt
            value_str = str(value).strip()
            if not value_str:
                return

            # Verificar si ya existe
            existing = (
                db.query(SecurityListEntry)
                .filter(SecurityListEntry.tenant_id == tenant_id)
                .filter(SecurityListEntry.list_type == list_type)
                .filter(SecurityListEntry.value == value_str)
                .filter(SecurityListEntry.rule_code == rule_code)
                .filter(SecurityListEntry.list_name == list_name)
                .first()
            )
            if existing:
                skipped_cnt += 1
                return

            entry = SecurityListEntry(
                tenant_id=tenant_id,
                list_type=list_type,
                value=value_str,
                value_type=value_type,
                list_name=list_name,
                rule_code=rule_code,
                reason=reason,
                enabled=True,
                created_by="migration_script",
            )
            db.add(entry)
            db.flush()

            audit = SecurityListAudit(
                entry_id=entry.id,
                action="create",
                new_value=json.dumps(entry.to_dict(), default=str),
                performed_by="migration_script",
                reason="Importación masiva inicial desde archivos JSON",
            )
            db.add(audit)
            inserted_cnt += 1

        # 1. trust_list.json
        if trust_json.exists():
            print(f"-> Migrando {trust_json.name}...")
            data = json.loads(trust_json.read_text(encoding="utf-8"))

            for ip in data.get("trusted_ips", []):
                _add_entry("global", "whitelist_ip", ip, "ip", reason="Migrado de trust_list.json trusted_ips")

            for country in data.get("trusted_countries", []):
                _add_entry("global", "trusted_country", country, "country_code", reason="Migrado de trust_list.json trusted_countries")

            for asn in data.get("trusted_asn_numbers", []):
                _add_entry("global", "trusted_asn", str(asn), "asn", reason="Migrado de trust_list.json trusted_asn_numbers")

            servers = data.get("servers", {})
            if isinstance(servers, dict):
                for srv_name, payload in servers.items():
                    if isinstance(payload, dict):
                        for ip in payload.get("server_ips", []):
                            _add_entry("global", "trusted_server", ip, "ip", list_name=srv_name, reason="Migrado de trust_list.json servers")

            lists = data.get("lists", {})
            if isinstance(lists, dict):
                for lname, items in lists.items():
                    if isinstance(items, list):
                        for item in items:
                            _add_entry("global", "list_ref", item, "token", list_name=lname, reason=f"Migrado de trust_list.json lists.{lname}")

        # 2. blacklistmaster_ignore.json
        if blm_ignore_json.exists():
            print(f"-> Migrando {blm_ignore_json.name}...")
            data = json.loads(blm_ignore_json.read_text(encoding="utf-8"))
            for ip in data.get("ips", []):
                _add_entry("global", "blm_ignore", ip, "ip", reason="Migrado de blacklistmaster_ignore.json")
            for cidr in data.get("cidrs", []):
                _add_entry("global", "blm_ignore", cidr, "cidr", reason="Migrado de blacklistmaster_ignore.json")

        # 3. blacklistmaster_shared.json
        if blm_shared_json.exists():
            print(f"-> Migrando {blm_shared_json.name}...")
            data = json.loads(blm_shared_json.read_text(encoding="utf-8"))
            servers = data.get("servers", {})
            if isinstance(servers, dict):
                for srv_name, payload in servers.items():
                    if isinstance(payload, dict):
                        for ip in payload.get("server_ips", []):
                            _add_entry("global", "blm_shared", ip, "ip", list_name=srv_name, reason="Migrado de blacklistmaster_shared.json")

        # 4. blacklistmaster_pmg.json
        if blm_pmg_json.exists():
            print(f"-> Migrando {blm_pmg_json.name}...")
            data = json.loads(blm_pmg_json.read_text(encoding="utf-8"))
            servers = data.get("servers", {})
            if isinstance(servers, dict):
                for srv_name, payload in servers.items():
                    if isinstance(payload, dict):
                        for ip in payload.get("server_ips", []):
                            _add_entry("global", "blm_pmg", ip, "ip", list_name=srv_name, reason="Migrado de blacklistmaster_pmg.json")

        db.commit()

    # Forzar refresco de caché
    SecurityListService.get_instance().refresh_cache()
    print(f"=== Migración finalizada con éxito: {inserted_cnt} entradas insertadas, {skipped_cnt} ya existían. ===")


if __name__ == "__main__":
    migrate()
