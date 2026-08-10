# Mecanismos de Autenticación y API Keys - SentinelX SIEM

## 1. Métodos de Autenticación Soportados

1. **Tokens JWT (Panel Dashboard & Usuarios)**:
   - Cabecera: `Authorization: Bearer <token_jwt>`
   - Emisión: Endpoint `/auth/login`
   - Resuelve el usuario, tenant y rol en PostgreSQL.

2. **Agente Linux API Key (`X-API-Key`)**:
   - Cabecera: `X-API-Key: sx_live_<entropy_token>`
   - Validación: Hash **SHA-256** en la tabla `agent_api_keys`.
   - Asigna automáticamente el `tenant_id` y rol `analyst` para la ingesta.

---

## 2. Gestión de API Keys de Agentes

```bash
# Crear nueva API Key para agente
python -c "from app.db import SessionLocal; from app.services.agent_api_key_service import create_agent_api_key; db = SessionLocal(); raw_key, rec = create_agent_api_key(db, name='srv-cpanel-01', tenant_id='tenant-acme'); print('RAW KEY:', raw_key)"

# Revocar API Key existente
python -c "from app.db import SessionLocal; from app.services.agent_api_key_service import revoke_agent_api_key; db = SessionLocal(); revoke_agent_api_key(db, 'key_uuid_here')"
```
