# Checklist Pre-Despliegue a Producción — SentinelX SIEM

Utilice esta lista de verificación antes de liberar o poner en marcha la instalación de **SentinelX SIEM** en un entorno de producción real.

---

## 1. Seguridad y Credenciales
- [ ] Se cambió la contraseña predeterminada del usuario administrador inicial (`INITIAL_ADMIN_PASSWORD`).
- [ ] La variable `SECRET_KEY` en `.env` cuenta con al menos 64 caracteres aleatorios seguros.
- [ ] El archivo `.env` en el servidor cuenta con permisos restringidos de lectura (`chmod 600`).
- [ ] No existen claves privadas, credenciales reales ni archivos `.env` versionados en el repositorio Git.

## 2. Base de Datos e Infraestructura
- [ ] PostgreSQL responde correctamente en el puerto `5432` y las migraciones Alembic están en la última versión (`head`).
- [ ] OpenSearch responde en el puerto `9200` con autenticación activa.
- [ ] MinIO está en ejecución y el bucket `sentinelx-evidence` fue creado.
- [ ] NATS JetStream responde correctamente en el puerto `4222`.

## 3. Servicios Systemd y Aislamiento
- [ ] Las unidades `sentinelx-api.service`, `sentinelx-worker.service`, `sentinelx-ingest.service` y `sentinelx-frontend.service` están activas (`systemctl is-active`).
- [ ] Los servicios están configurados para reinicio automático (`Restart=always`).
- [ ] El proyecto está aislado bajo `/opt/sentinelx` ejecutándose con el usuario dedicado `sentinelx`.
- [ ] Los logs de instalación se registran en `/var/log/sentinelx/install.log`.

## 4. Frontend Web
- [ ] La compilación estática de Astro (`npm run build`) se ejecutó sin errores.
- [ ] El login y el Dashboard cargan correctamente en el navegador.
- [ ] Las pestañas de Alertas, Incidentes, Entidades, Hunting, Reportes y Listas de Seguridad responden sin errores 404 ni 500.

## 5. Agentes de Ingesta
- [ ] El instalador `install_sentinelx_agent.sh` está disponible y probado en un cliente Linux.
- [ ] Las API Keys generadas bajo `/dashboard/api-keys` autentican correctamente la ingesta.
