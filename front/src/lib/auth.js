/**
 * SentinelX SIEM - Módulo de Gestión de Sesión y Autenticación (AuthContext)
 */

const TOKEN_KEY = "sentinelx_token";

const ROLE_PERMISSIONS = {
  admin: [
    "ingest.read",
    "alerts.read",
    "alerts.manage",
    "incidents.manage",
    "agents.manage",
    "configuration.manage",
  ],
  analyst: ["ingest.read", "alerts.read", "alerts.manage", "incidents.manage"],
  operator: ["ingest.read", "alerts.read"],
  viewer: ["ingest.read", "alerts.read"],
};

/**
 * Decodifica de forma segura un token JWT sin librerías externas.
 * @param {string} token
 * @returns {object|null}
 */
export function parseJwt(token) {
  if (!token || typeof token !== "string") return null;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (err) {
    console.error("Error al decodificar token JWT:", err);
    return null;
  }
}

/**
 * Obtiene el token activo de localStorage o sessionStorage.
 * @returns {string|null}
 */
export function getToken() {
  if (typeof window === "undefined") return null;
  return (
    sessionStorage.getItem(TOKEN_KEY) ||
    localStorage.getItem(TOKEN_KEY) ||
    window.SENTINELX_TOKEN ||
    null
  );
}

/**
 * Almacena el token de sesión.
 * @param {string} token
 * @param {boolean} remember
 */
export function setToken(token, remember = false) {
  if (typeof window === "undefined") return;
  if (remember) {
    localStorage.setItem(TOKEN_KEY, token);
    sessionStorage.removeItem(TOKEN_KEY);
  } else {
    sessionStorage.setItem(TOKEN_KEY, token);
    localStorage.removeItem(TOKEN_KEY);
  }
  window.SENTINELX_TOKEN = token;
}

/**
 * Elimina la sesión actual.
 */
export function clearToken() {
  if (typeof window === "undefined") return;
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  delete window.SENTINELX_TOKEN;
}

/**
 * Retorna el contexto completo de autenticación (AuthContext).
 * @returns {{
 *   authenticated: boolean,
 *   user_id: number|null,
 *   username: string,
 *   tenant_id: string,
 *   role: string,
 *   permissions: string[]
 * }}
 */
export function getAuthContext() {
  const token = getToken();
  if (!token) {
    return {
      authenticated: false,
      user_id: null,
      username: "invitado",
      tenant_id: "default",
      role: "viewer",
      permissions: ROLE_PERMISSIONS["viewer"],
    };
  }

  const payload = parseJwt(token);
  if (!payload) {
    clearToken();
    return {
      authenticated: false,
      user_id: null,
      username: "invitado",
      tenant_id: "default",
      role: "viewer",
      permissions: ROLE_PERMISSIONS["viewer"],
    };
  }

  // Verificar expiración exp
  if (payload.exp && payload.exp * 1000 < Date.now()) {
    console.warn("Token JWT expirado");
    clearToken();
    return {
      authenticated: false,
      user_id: null,
      username: "expirado",
      tenant_id: "default",
      role: "viewer",
      permissions: [],
    };
  }

  const role = payload.role || "admin"; // Fallback dev
  const tenant_id = payload.tenant_id || payload.tenant || "default";

  return {
    authenticated: true,
    user_id: payload.sub ? parseInt(payload.sub, 10) : null,
    username: payload.email || payload.username || `Usuario #${payload.sub}`,
    tenant_id: tenant_id,
    role: role,
    permissions: ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS["viewer"],
  };
}

/**
 * Verifica si el contexto actual posee el permiso especificado.
 * @param {string} permission
 * @returns {boolean}
 */
export function can(permission) {
  const ctx = getAuthContext();
  if (ctx.role === "admin") return true;
  return ctx.permissions.includes(permission);
}

/**
 * Verifica si el usuario posee un rol específico.
 * @param {string} roleName
 * @returns {boolean}
 */
export function hasRole(roleName) {
  const ctx = getAuthContext();
  return ctx.role === roleName;
}

/**
 * Cierra la sesión y redirige al login.
 */
export function logout() {
  clearToken();
  if (typeof window !== "undefined") {
    window.location.href = "/login";
  }
}

/**
 * Helper para redirección de protección de rutas en páginas protegidas.
 */
export function requireAuth() {
  if (typeof window === "undefined") return;
  const ctx = getAuthContext();
  if (!ctx.authenticated) {
    window.location.href = "/login";
  }
  return ctx;
}
