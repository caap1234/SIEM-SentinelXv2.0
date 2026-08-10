# Reporte de Estabilización y Corrección Post-Despliegue — SentinelX SIEM

Este documento resume los resultados, correcciones y validaciones realizadas durante la **Fase de Estabilización** posterior al primer despliegue local de SentinelX SIEM.

---

## 1. Errores Encontrados y Correcciones Realizadas

### 1.1 Autenticación API & AuthContext Frontend (HTTP 401)
- **Problema**: Componentes como `ActivityChart.astro` realizaban llamadas a endpoints como `/dashboard/activity` sin la ruta canónica `/api/v1/dashboard/activity` y sin incluir el token JWT en las cabeceras.
- **Corrección**:
  - `ActivityChart.astro`: Actualizada la URL a `/api/v1/dashboard/activity` y configurada la función `getAuthToken()` para recuperar el JWT activo desde `sessionStorage`/`localStorage`.
  - `app/schemas/dependencies.py`: Ajustada la resolución del `user_role` en `get_current_auth_context` para que los usuarios con `is_admin=True` reciban `ROLE_ADMIN` ("admin"), mientras que las cuentas estándar sin permisos elevados reciban `ROLE_ANALYST` en lugar del valor por defecto indiscriminado.

### 1.2 Estética Visual & Eliminación de Emojis
- **Problema**: Se utilizaban emojis (`🔍`, `🔄`, `📦`) en botones de acción principales.
- **Corrección**: Reemplazados por iconos SVG inline escalables, nítidos y vectoriales alineados con la identidad visual SentinelX (paleta `#E67E22`, `#10B981`, `#3B82F6`).

### 1.3 Modelo de Evidencia Forense S3 & Navegación
- **Problema**: La vista de evidencia mostraba etiquetas técnicas redundantes como `"Prefijo S3: sentinelx-evidence/tenant/"`.
- **Corrección**:
  - `evidence.astro`: Reestructurado el panel de filtros para mostrar las etiquetas profesionales `Tenant: default` y `Ruta de Evidencia: default/YYYY/MM/DD/`.
  - El modal de inspección forense despliega el evento normalizado ECS, el log crudo original, timestamps UTC, metadatos del host, parser utilizado y hash SHA-256 de verificación.

### 1.4 Relación Alertas ➔ Incidentes ➔ Entidades ➔ Evidencia
- **Problema**: El script de carga inicial no creaba registros en `entities` ni relacionaba `incident_alerts` o `incident_entities`.
- **Corrección**:
  - `scripts/seed_test_data.py`: Actualizado para poblar registros de prueba en las tablas `entities` (IP atacante, Host, Usuario root), asociando la alerta `SSH Brute Force` y `ModSecurity SQLi` con el incidente `INC-SEC-01` e IP `198.51.100.45`.

### 1.5 Alineación Visual de Tarjetas KPI en Dashboard
- **Problema**: Inconsistencias en padding, alturas y alineación de números en las tarjetas KPI del SOC.
- **Corrección**:
  - `StatsCard.astro`: Homogeneizado a `p-5 justify-between h-full shadow-sm gap-2` con tipografía de números `text-2xl font-bold` y etiquetas `text-[11px] font-semibold tracking-wider`.
  - `index.astro`: Eliminado bloque de código duplicado al final del archivo.

### 1.6 Sidebar Global Reorganizado & Menú Colapsable
- **Problema**: El sidebar sufría variaciones de ancho según el contenido de la vista activa y la lista de opciones era excesivamente extensa.
- **Corrección**:
  - `Sidebar.astro`: Fijado el ancho a `w-64 shrink-0 min-h-screen border-r border-black/20` para prevenir cualquier salto de maquetación.
  - Reorganizado el menú en 4 categorías claras:
    1. **Dashboard**: Dashboard (`/dashboard`)
    2. **Operaciones SOC**: Alertas, Incidentes, Threat Hunting, Entidades, Procesos
    3. **Ingesta & Evidencia**: Agentes Linux, Cargar Logs, API Keys, Evidencia S3
    4. **Administración**: Submenú desplegable/colapsable con flecha animada que agrupa *Reglas Detección*, *Reglas Incidentes* y *Configuración*.

### 1.7 Bootstrap de Usuario Administrador Inicial
- **Problema**: Requerido test automatizado de verificación de credenciales de bootstrap y permisos RBAC.
- **Corrección**: Creado test unitario `tests/unit/test_admin_bootstrap.py` para validar que `seed_admin_user` genera el usuario con `is_admin=True`, rol `admin` y acceso total a todas las políticas RBAC.

### 1.8 Validación OpenSearch & Threat Hunting
- **Problema**: La búsqueda por defecto en `search_events` apuntaba al stream `sentinelx-events-hosting-default` en lugar del comodín de tenant.
- **Corrección**:
  - `app/core/opensearch_client.py`: Actualizada la firma de `search_events` a `target_stream: str = "sentinelx-events-*"` permitiendo consultar de forma transparente todos los Data Streams ECS del tenant.

---

## 2. Matriz de Validación de Pruebas

| Prueba / Suite | Comando | Resultado | Notas |
|---|---|---|---|
| **Backend Unit Tests** | `.venv/bin/pytest --no-header -q` | **96 Passed** (0 Failures) | 100% de la suite pasando (39% cobertura general) |
| **Admin Bootstrap Test** | `.venv/bin/pytest tests/unit/test_admin_bootstrap.py` | **1 Passed** | Verificación de `is_admin=True` y permisos RBAC |
| **Astro Type Check** | `npm run check` (en `front/`) | **0 Errors, 0 Warnings** | Diagnósticos TypeScript y Astro limpios |
| **Frontend Build** | `npm run build` (en `front/`) | **17/17 Pages Built** | Bundle estático generado en 1.19s |
| **Dashboard Activity API** | `GET /api/v1/dashboard/activity` | **HTTP 200 OK** | Retorna la serie temporal para la gráfica de actividad |
| **Threat Hunting Search** | `GET /api/v1/hunting/search` | **HTTP 200 OK** | Retorna eventos desde OpenSearch con tenant isolation |

---

## 3. Estado Final del Sistema

El stack de **SentinelX-SIEM** ha sido verificado y se encuentra **estabilizado**:

- 🟢 **Servicios**: PostgreSQL, OpenSearch, MinIO y NATS responden correctamente.
- 🟢 **Autenticación**: JWT centralizado funcionando sin deslogueos ni errores `401`.
- 🟢 **Interfaz SOC**: Sidebar de ancho fijo, menú desplegable de administración e iconos SVG limpios.
- 🟢 **Datos de Prueba**: Flujo completo de Incidentes ➔ Alertas ➔ Entidades ➔ Evidencia MinIO ➔ Eventos OpenSearch verificado.
