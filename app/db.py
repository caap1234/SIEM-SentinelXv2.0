import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import settings

# Engine de SQLAlchemy
engine = create_engine(
    settings.DATABASE_URL,
    future=True,
    echo=False,  # pon True si quieres ver el SQL en consola
    pool_pre_ping=True,
)

# Factoría de sesiones
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,  # <- evita expirar instancias ORM tras commit (clave para engine cache)
)

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB, ARRAY, INET

from sqlalchemy import BigInteger

@compiles(BigInteger, "sqlite")
def compile_bigint_sqlite(type_, compiler, **kw):
    return "INTEGER"

@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

@compiles(ARRAY, "sqlite")
def compile_array_sqlite(type_, compiler, **kw):
    return "JSON"

@compiles(INET, "sqlite")
def compile_inet_sqlite(type_, compiler, **kw):
    return "VARCHAR(45)"

# Custom bind processor for ARRAY on SQLite dialect
if not hasattr(ARRAY, "_sqlite_bind_processor_added"):
    _orig_bind = ARRAY.bind_processor
    def _sqlite_bind_processor(self, dialect):
        if dialect and dialect.name == "sqlite":
            return lambda value: json.dumps(list(value)) if isinstance(value, (list, tuple, set)) else value
        return _orig_bind(self, dialect)
    ARRAY.bind_processor = _sqlite_bind_processor
    ARRAY._sqlite_bind_processor_added = True

# Base para los modelos ORM
Base = declarative_base()


# Dependencia para usar en FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
