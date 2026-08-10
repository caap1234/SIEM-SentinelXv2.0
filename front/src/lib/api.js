/**
 * SentinelX SIEM - Cliente API Centralizado (Vanilla JS / Fetch Wrapper)
 */

import { getToken, clearToken } from "./auth.js";

const API_BASE = import.meta.env.PUBLIC_API_URL || "http://127.0.0.1:8000";

export class ApiError extends Error {
  constructor(message, status, data = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

/**
 * Petición HTTP centralizada con inyección de token, manejo de 401/403 y timeouts.
 * @param {string} endpoint - Ruta del endpoint (ej. "/api/v2/alerts" o "dashboard/kpis")
 * @param {RequestInit & { timeout?: number }} options
 * @returns {Promise<any>}
 */
export async function apiFetch(endpoint, options = {}) {
  const { timeout = 15000, headers = {}, ...customConfig } = options;

  // Construir URL completa
  const url = endpoint.startsWith("http")
    ? endpoint
    : `${API_BASE}${endpoint.startsWith("/") ? "" : "/"}${endpoint}`;

  // Inyectar Token de Autorización si está presente
  const token = getToken();
  const authHeaders = {};
  if (token) {
    authHeaders["Authorization"] = `Bearer ${token}`;
  }

  const defaultHeaders = {
    Accept: "application/json",
    ...authHeaders,
    ...headers,
  };

  // Configurar timeout con AbortController
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...customConfig,
      headers: defaultHeaders,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    // Manejo de códigos HTTP de error
    if (!response.ok) {
      // 401 Unauthorized -> Sesión no válida o expirada
      if (response.status === 401) {
        console.warn("Respuesta 401 de la API: Redirigiendo a /login");
        clearToken();
        if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
          window.location.href = "/login";
        }
      }

      // 403 Forbidden -> Permisos insuficientes por RBAC
      if (response.status === 403) {
        console.warn("Respuesta 403 Forbidden: Acceso denegado por permiso RBAC");
        if (typeof window !== "undefined") {
          window.dispatchEvent(
            new CustomEvent("sentinelx:access-denied", {
              detail: { endpoint, status: 403 },
            })
          );
        }
      }

      let errorData = null;
      try {
        errorData = await response.json();
      } catch (_) {
        errorData = await response.text();
      }

      const errorMsg =
        (typeof errorData === "object" && (errorData.detail || errorData.message)) ||
        `Error HTTP ${response.status}: ${response.statusText}`;

      throw new ApiError(errorMsg, response.status, errorData);
    }

    // 204 No Content
    if (response.status === 204) {
      return null;
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      throw new ApiError("La solicitud excedió el tiempo límite de espera (timeout)", 408);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(err.message || "Error de red o conexión no disponible", 0);
  }
}

/**
 * Petición GET con soporte para parámetros de consulta.
 * @param {string} endpoint
 * @param {Record<string, any>} params
 * @returns {Promise<any>}
 */
export async function apiGet(endpoint, params = {}) {
  let url = endpoint;
  if (params && Object.keys(params).length > 0) {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") {
        query.append(k, String(v));
      }
    });
    const queryString = query.toString();
    if (queryString) {
      url += (url.includes("?") ? "&" : "?") + queryString;
    }
  }
  return apiFetch(url, { method: "GET" });
}

/**
 * Petición POST enviando JSON.
 * @param {string} endpoint
 * @param {any} data
 * @returns {Promise<any>}
 */
export async function apiPost(endpoint, data = {}) {
  return apiFetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

/**
 * Petición PUT enviando JSON.
 * @param {string} endpoint
 * @param {any} data
 * @returns {Promise<any>}
 */
export async function apiPut(endpoint, data = {}) {
  return apiFetch(endpoint, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

/**
 * Petición DELETE.
 * @param {string} endpoint
 * @returns {Promise<any>}
 */
export async function apiDelete(endpoint) {
  return apiFetch(endpoint, { method: "DELETE" });
}

/**
 * Petición PATCH enviando JSON.
 * @param {string} endpoint
 * @param {any} data
 * @returns {Promise<any>}
 */
export async function apiPatch(endpoint, data = {}) {
  return apiFetch(endpoint, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}
