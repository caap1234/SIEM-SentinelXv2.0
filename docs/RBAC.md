# Matriz de Roles y Permisos Granulares (RBAC) - SentinelX SIEM

## Matriz de Permisos por Rol

| Permiso | `admin` | `analyst` | `operator` | `viewer` | Descripción |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `ingest.read` |  |  |  |  | Lectura de métricas e ingesta. |
| `alerts.read` |  |  |  |  | Lectura de alertas e incidentes. |
| `alerts.manage` |  |  |  |  | Modificación del estado de alertas. |
| `incidents.manage` |  |  |  |  | Gestión y asignación de incidentes. |
| `agents.manage` |  |  |  |  | Registro, actualización y revocación de agentes. |
| `configuration.manage` |  |  |  |  | Configuración del sistema y reglas globales. |

---

## Uso en Endpoints FastAPI

```python
from app.schemas.dependencies import require_permission, AuthContext

@router.get("/alerts")
def get_alerts(ctx: AuthContext = Depends(require_permission("alerts.read"))):
    # ctx.tenant_id contiene el tenant resuelto de forma segura
    pass
```
