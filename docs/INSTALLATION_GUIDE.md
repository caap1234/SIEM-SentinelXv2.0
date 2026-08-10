# Guía de Instalación y Despliegue de Producción — SentinelX SIEM

Esta guía detalla los pasos para realizar la primera instalación de producción de **SentinelX SIEM** en un servidor VPS limpio o en un VPS que coexista con **cPanel/WHM**.

---

## 1. Requisitos Mínimos del Servidor VPS

- **Sistema Operativo**: AlmaLinux 8/9, Rocky Linux 8/9, RHEL 8/9, Ubuntu 20.04/22.04/24.04, Debian 11/12.
- **CPU**: 4 Cores dedicados.
- **RAM**: 8 GB RAM (16 GB recomendados para volumen alto de logs).
- **Disco**: 80 GB SSD/NVMe (ajustable según política de retención).
- **Python**: Python >= 3.10.
- **Node.js**: Node.js >= 18.x + `npm`.

---

## 2. Matriz de Puertos y Servicios

SentinelX SIEM utiliza puertos dedicados para evitar conflictos con cPanel u otros servicios web en el VPS:

| Servicio | Puerto por Defecto | Protocolo | Descripción |
|----------|-------------------|-----------|-------------|
| **Frontend Web** | `4321` (o 80/443 via Nginx) | HTTP/HTTPS | Panel Astro Web |
| **API Backend** | `8000` | HTTP | FastAPI REST API |
| **PostgreSQL** | `5432` | TCP | Base de datos principal de estado |
| **OpenSearch** | `9200` | HTTP | Motor de analítica y eventos |
| **MinIO API** | `9000` | HTTP | Almacenamiento S3 de evidencias |
| **MinIO Console**| `9001` | HTTP | Consola de administración MinIO |
| **NATS JetStream** | `4222` | TCP | Queue / Pipeline de ingesta |

> **Nota para servidores con cPanel**: Los puertos de cPanel (2082, 2083, 2086, 2087, 80/443 Apache, 3306 MySQL, 25/587 Exim) no entran en conflicto con la matriz de puertos de SentinelX.

---

## 3. Instalación Paso a Paso

### Paso 1: Clonar el Repositorio
```bash
cd /opt
git clone https://github.com/tu-organizacion/SentinelX-SIEM.git sentinelx
cd /opt/sentinelx
```

### Paso 2: Ejecutar el Instalador Automatizado
Ejecute el script de instalación de producción como `root`:

```bash
chmod +x setup_sentinelx.sh
./setup_sentinelx.sh
```

El script ejecutará automáticamente:
1. Verificación de SO y dependencias.
2. Detección de cPanel y ajuste de CSF firewall si aplica.
3. Generación del archivo `.env` de producción (con permisos `600`).
4. Creación del entorno virtual de Python `.venv` e instalación de dependencias.
5. Construcción del frontend estático Astro (`npm run build`).
6. Inicialización síncrona `scripts/initial_setup.py` (migraciones Alembic, usuario admin inicial, bucket MinIO `sentinelx-evidence`, índices OpenSearch y listas de seguridad).
7. Instalación de unidades de servicio `systemd` bajo `/etc/systemd/system/sentinelx-*.service`.

---

## 4. Gestión de Servicios Systemd

Para controlar los servicios de SentinelX en producción:

```bash
# Ver estado de todos los servicios
systemctl status sentinelx-api sentinelx-worker sentinelx-ingest sentinelx-frontend

# Iniciar o reiniciar todos los servicios
systemctl restart sentinelx-api sentinelx-worker sentinelx-ingest sentinelx-frontend

# Consultar logs en tiempo real
journalctl -u sentinelx-api -f
journalctl -u sentinelx-worker -f
```

---

## 5. Solución de Problemas Frecuentes

1. **Error de Conexión a PostgreSQL / OpenSearch**:
   Verifique que los servicios de BD estén corriendo y que `.env` contenga la cadena `DATABASE_URL` correcta.

2. **Bloqueo por CSF Firewall en cPanel**:
   Asegúrese de contar con `DOCKER="1"` o los puertos 8000, 4321 habilitados en `/etc/csf/csf.conf` mediante `csf -r`.

3. **Re-ejecución Segura (Idempotencia)**:
   El script `setup_sentinelx.sh` puede re-ejecutarse en cualquier momento sin riesgo de pérdida de datos. Preservará el archivo `.env` existente y actualizará únicamente el código y servicios.
