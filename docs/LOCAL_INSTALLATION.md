# Guía de Instalación y Despliegue Local de SentinelX SIEM

Documentación oficial para levantar y probar el stack completo de **SentinelX SIEM** en un entorno local o de desarrollo.

---

## 1. Requisitos del Sistema

### Software Requerido
- **Docker Desktop** / **Docker Engine**: v24.0+ con `docker compose` v2.20+
- **Python**: v3.9+ (con virtualenv habilitado)
- **Node.js**: v18+ y `npm` (para ejecutar la consola web Astro)
- **Git**

### Recursos Recomendados
- **CPU**: 4 núcleos o superior
- **RAM**: 8 GB mínimo (OpenSearch requiere ~1 GB asignado)
- **Almacenamiento**: 10 GB libres

---

## 2. Puertos Utilizados

| Servicio | Puerto Host | Descripción |
|---|---|---|
| **Frontend Console** | `4321` | Consola Web SOC (Astro JS + Tailwind v4) |
| **Backend API** | `8000` | API REST FastAPI |
| **PostgreSQL** | `5432` | Base de datos transaccional |
| **OpenSearch** | `9200` | Motor de búsqueda y Data Streams |
| **OpenSearch Metrics** | `9600` | Métricas de OpenSearch |
| **NATS Event Bus** | `4222` | Broker de eventos JetStream |
| **NATS Management** | `8222` | Consola/Health NATS |
| **MinIO API (S3)** | `9000` | Almacenamiento de evidencia cruda |
| **MinIO Console** | `9001` | Consola Web MinIO |

---

## 3. Configuración del Entorno Local

### 3.1 Clonar Repositorio y Entorno Python
```bash
git clone https://github.com/SentinelX/SentinelX-SIEM.git
cd SentinelX-SIEM

# Crear y activar entorno virtual
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Crear Archivo de Variables de Entorno (`.env`)
Copiar el archivo de configuración `.env.local` a `.env`:

```bash
cp .env.local .env
```

Las variables clave en `.env` son:
```env
POSTGRES_DB=sentinelx_db
POSTGRES_USER=sentinelx
POSTGRES_PASSWORD=SentinelX_Local_2026!
POSTGRES_PORT=5432

DATABASE_URL=postgresql://sentinelx:SentinelX_Local_2026!@localhost:5432/sentinelx_db
SECRET_KEY=900a0af36154929dd4bc8a14a1de0511637d369d72af37111e026540dd2dd8ef

INITIAL_ADMIN_EMAIL=admin@sentinelx.local
INITIAL_ADMIN_PASSWORD=SentinelX_Admin_2026!

OPENSEARCH_URL=http://localhost:9200
NATS_URL=nats://localhost:4222
MINIO_ENDPOINT=http://localhost:9000
```

---

## 4. Inicio del Stack de Infraestructura con Docker

Para levantar los contenedores de la infraestructura base (PostgreSQL, NATS, OpenSearch, MinIO):

```bash
docker compose -f docker-compose.local.yml up -d db nats opensearch minio
```

Verificar el estado de salud de los contenedores:
```bash
docker compose -f docker-compose.local.yml ps
```

---

## 5. Aplicar Migraciones e Iniciar el Backend

### 5.1 Ejecutar Migraciones de Alembic
```bash
.venv/bin/alembic upgrade head
```

### 5.2 Cargar Datos de Prueba Iniciales
```bash
.venv/bin/python scripts/seed_test_data.py
```

### 5.3 Iniciar el Servidor Backend (FastAPI)
```bash
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

El backend estará disponible en: **`http://localhost:8000`**
Documentación Swagger / OpenAPI: **`http://localhost:8000/docs`**

---

## 6. Iniciar los Workers Asíncronos

En terminales independientes (o en segundo plano):

```bash
# Worker de Indexación en OpenSearch
.venv/bin/python -m app.workers.opensearch_indexer_worker

# Worker de Evidencia en MinIO
.venv/bin/python -m app.workers.minio_evidence_worker

# Worker de Correlación
.venv/bin/python -m app.workers.engine_worker_loop

# Worker de Parsing
.venv/bin/python -m app.workers.parsing_worker_loop
```

---

## 7. Iniciar el Frontend (Consola SOC)

```bash
cd front
npm install
npm run dev
```

La consola web estará disponible en: **`http://localhost:4321`**

---

## 8. Credenciales Iniciales de Prueba

| Elemento | Credencial |
|---|---|
| **Consola Web (SOC Dashboard)** | `http://localhost:4321/login` |
| **Email Administrador** | `admin@sentinelx.local` |
| **Contraseña Administrador** | `SentinelX_Admin_2026!` |
| **Tenant ID por Defecto** | `default` |
| **API Key Agente Linux** | `sx_live_demoagentkey001.sec8839219380123849102` |
| **MinIO Console** | `http://localhost:9001` (user: `minioadmin` / pass: `minioadmin`) |
| **OpenSearch Health** | `http://localhost:9200/_cluster/health` |

---

## 9. Verificación de Funcionamiento

1. **Dashboard SOC**: Iniciar sesión en `http://localhost:4321/login`. Los KPIs de eventos, alertas e indicadores de estado deben estar visibles.
2. **Alertas e Incidentes**: Navegar a `/dashboard/alertas` e `/dashboard/incidentes` para verificar las alertas e incidentes de prueba cargados.
3. **Evidencia S3**: En el modal de detalle de cualquier alerta, hacer clic en "Ver Evidencia Forense MinIO (S3)" para descargar y verificar el paquete `.json.gz`.
4. **Threat Hunting**: Navegar a `/dashboard/hunting` para realizar consultas KQL sobre los eventos almacenados en OpenSearch.
5. **Agentes Linux**: Navegar a `/dashboard/agentes` para inspeccionar el agente de prueba registrado y su telemetría heartbeat.
