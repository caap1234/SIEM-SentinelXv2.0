#!/usr/bin/env python3
"""
Script autónomo para exportar todas las reglas V2 (RuleV2) y sus Bindings asociadas
desde PostgreSQL a un archivo JSON estructurado (rules_v2_export.json).
"""
import json
import os
import sys
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

def get_database_url():
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL="):
                    return line.split("=", 1)[1].strip('"\'')
    
    return "postgresql://sentinelx:sentinelx@db:5432/sentinelx_db"

def default_json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def export_rules():
    db_url = get_database_url()
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        print("[*] Consultando Reglas V2 y sus Bindings en PostgreSQL...")
        
        # Consultar todas las reglas
        rules_rows = db.execute(text("""
            SELECT id, name, description, enabled, source, event_type, severity, 
                   match, group_by, window_seconds, let, condition, cooldown_seconds, 
                   evidence, emit, tags, version, detection_bindings_operator, 
                   legacy_list_policy, created_at, updated_at
            FROM rules_v2
            ORDER BY id ASC;
        """)).mappings().all()

        # Consultar todos los bindings
        bindings_rows = db.execute(text("""
            SELECT id, rule_id, list_name, role, match_field, operator, action_config, enabled, created_at
            FROM rule_list_bindings
            ORDER BY rule_id ASC, id ASC;
        """)).mappings().all()

        # Agrupar bindings por rule_id
        bindings_by_rule = {}
        for b in bindings_rows:
            b_dict = dict(b)
            rid = b_dict["rule_id"]
            if rid not in bindings_by_rule:
                bindings_by_rule[rid] = []
            bindings_by_rule[rid].append(b_dict)

        exported_rules = []
        for r in rules_rows:
            r_dict = dict(r)
            rid = r_dict["id"]
            r_dict["bindings"] = bindings_by_rule.get(rid, [])
            exported_rules.append(r_dict)

        output_filename = "rules_v2_export.json"
        export_data = {
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "total_rules": len(exported_rules),
            "rules": exported_rules
        }

        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=default_json_serializer)

        print(f"[+] ¡Éxito! {len(exported_rules)} reglas exportadas exitosamente a '{output_filename}'.")

    except Exception as e:
        print(f"[!] Error exportando reglas: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    export_rules()
