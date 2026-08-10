# Arquitectura de Autenticación Frontend, Cliente API y AuthContext

## 1. Cliente API Centralizado (`src/lib/api.js`)

El cliente API expone funciones asíncronas estándar (`apiGet`, `apiPost`, `apiPut`, `apiDelete`) que encapsulan la comunicación HTTP con el backend de SentinelX:

```javascript
import { apiGet, apiPost } from "../lib/api.js";

// Petición GET con parámetros automáticos e inyección de token
const data = await apiGet("/dashboard/kpis", { days: 7, server: "srv1" });

// Petición POST enviando JSON
const newRule = await apiPost("/api/v2/rules", { name: "Nueva Regla" });
```

### Características de `apiFetch`:
- **Inyección Automática de Token**: Lee `sentinelx_token` de `sessionStorage`/`localStorage` y agrega `Authorization: Bearer <token>`.
- **Intercepción 401 Unauthorized**: Limpia la sesión local y redirige al usuario a `/login`.
- **Intercepción 403 Forbidden**: Dispara un evento `sentinelx:access-denied` para alertar en la UI sin romper la ejecución.
- **Timeout**: Cancela peticiones colgadas después de 15 segundos (`AbortController`).

---

## 2. Contexto de Autenticación (`src/lib/auth.js`)

El módulo `auth.js` decodifica la carga útil del token JWT en el lado del cliente sin librerías pesadas externas:

```javascript
import { getAuthContext, can, hasRole, logout } from "../lib/auth.js";

const ctx = getAuthContext();
console.log(ctx.username); // "admin@sentinelx.io"
console.log(ctx.role);     // "admin"
console.log(ctx.tenant_id);// "tenant-acme"

// Comprobación RBAC para renderizado condicional en UI
if (can("alerts.manage")) {
  // Mostrar botón de resolución de alerta
}
```

---

## 3. Ayudante Global `window.SentinelXAuth`

`HeaderBar.astro` expone automáticamente el contexto `window.SentinelXAuth` a todas las páginas e islas Astro:

- `window.SentinelXAuth.getAuthContext()`
- `window.SentinelXAuth.can("permission.name")`
- `window.SentinelXAuth.hasRole("admin")`
- `window.SentinelXAuth.logout()`
