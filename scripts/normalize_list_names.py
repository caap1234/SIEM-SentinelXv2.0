#!/usr/bin/env python3
"""
Script para normalizar list_name en security_list_entries.
Asigna list_name = list_type para todos los registros que tengan list_name como NULL,
asegurando que las 15 listas tengan nombres explícitos utilizables en Rule Engine V2.
"""
import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

def get_database_url():
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    
    # Intentar leer desde .env si existe en el directorio del proyecto
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("DATABASE_URL="):
                    return line.split("=", 1)[1].strip('"\'')
    
    return "postgresql://sentinelx:sentinelx@db:5432/sentinelx_db"

def normalize_list_names():
    db_url = get_database_url()
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        print("[*] Normalizando list_name en security_list_entries...")
        
        # 1. Asignar list_name = list_type donde list_name sea NULL o vacío
        res = db.execute(text("""
            UPDATE security_list_entries 
            SET list_name = list_type 
            WHERE list_name IS NULL OR list_name = '';
        """))
        db.commit()
        print(f"[+] Registros actualizados (list_name = list_type): {res.rowcount}")

        # 2. Resumen de listas por list_name
        res_summary = db.execute(text("""
            SELECT list_type, list_name, COUNT(*) as count 
            FROM security_list_entries 
            GROUP BY list_type, list_name 
            ORDER BY list_type, list_name;
        """)).fetchall()

        print("\n=== RESUMEN DE LISTAS DISPONIBLES EN EL SIEM ===")
        print(f"{'TYPE':<25} | {'NAME':<35} | {'ENTRADAS'}")
        print("-" * 70)
        for r in res_summary:
            print(f"{r.list_type:<25} | {r.list_name:<35} | {r.count}")

    except Exception as e:
        db.rollback()
        print(f"[!] Error normalizando nombres de listas: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    normalize_list_names()
