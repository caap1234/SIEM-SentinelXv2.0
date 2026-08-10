# Arquitectura RBAC en Frontend y Control de Acceso Visual

## 1. Principio Fundamental de Seguridad

> **IMPORTANTE**: El control RBAC implementado en la capa de interfaz de usuario (Astro JS / HTML / Tailwind) tiene como **único propósito optimizar la experiencia de usuario (UX)** ocultando o deshabilitando elementos a los que el usuario no tiene acceso.
>
> **La seguridad y autorización real radica en los verificadores RBAC del backend FastAPI (`require_permission`)**, los cuales bloquean cualquier intento de suplantación o petición API no autorizada con respuestas `401 Unauthorized` o `403 Forbidden`.

---

## 2. Matriz de Visibilidad UI por Rol

| Módulo / Elemento UI | Permiso Requerido | `admin` | `analyst` | `operator` | `viewer` |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Dashboard general** | `ingest.read` |  |  |  |  |
| **Alertas Detectadas (Lectura)** | `alerts.read` |  |  |  |  |
| **Acciones Masivas en Alertas** | `alerts.manage` |  |  |  |  |
| **Gestión de Incidentes** | `incidents.manage` |  |  |  |  |
| **Puntuación de Entidades** | `alerts.read` |  |  |  |  |
| **Monitoreo de Procesos** | `ingest.read` |  |  |  |  |
| **Subida de Logs** | `configuration.manage` |  |  |  |  |
| **Gestión de API Keys / Agentes** | `agents.manage` |  |  |  |  |
| **Reglas & Configuración System** | `configuration.manage` |  |  |  |  |

---

## 3. Uso del Componente `<PermissionGate />`

El componente `<PermissionGate />` permite renderizar condicionalmente secciones enteras o botones de la UI:

```astro
---
import PermissionGate from "../../components/auth/PermissionGate.astro";
---

<!-- Renderizado condicional por permiso -->
<PermissionGate permission="alerts.manage">
  <button class="bg-[#E67E22] text-white">Resolver Alerta</button>
</PermissionGate>

<!-- Renderizado condicional por rol -->
<PermissionGate role="admin">
  <button class="bg-[#DC2626] text-white">Eliminar Agente</button>
</PermissionGate>

<!-- Renderizado condicional si cumple AL MENOS UNO de los permisos -->
<PermissionGate anyPermissions={["incidents.manage", "alerts.manage"]}>
  <div class="bulk-actions-bar">...</div>
</PermissionGate>
```

---

## 4. Atributos Declarativos `data-rbac-gate` y `data-rbac-permission`

Para elementos HTML directos en páginas o plantillas, se puede agregar el atributo `data-rbac-gate` y `data-rbac-permission`:

```html
<div class="bulk-bar" data-rbac-gate data-rbac-permission="alerts.manage">
  <!-- Botones de administración masiva -->
</div>
```

Los scripts automáticos de `rbac.js` evalúan estos atributos en la carga inicial y ocultan automáticamente los elementos no autorizados (`display: none`).
