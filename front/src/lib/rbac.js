/**
 * SentinelX SIEM - Utilidades de Verificación de Permisos RBAC en Frontend
 */

import { getAuthContext, can as authCan, hasRole as authHasRole, logout as authLogout } from "./auth.js";

export function logout() {
  authLogout();
}


/**
 * Verifica si el usuario autenticado posee un permiso específico.
 * @param {string} permission
 * @returns {boolean}
 */
export function can(permission) {
  return authCan(permission);
}

/**
 * Verifica si el usuario autenticado posee un rol específico.
 * @param {string} roleName
 * @returns {boolean}
 */
export function hasRole(roleName) {
  return authHasRole(roleName);
}

/**
 * Verifica si el usuario autenticado posee AL MENOS UNO de los permisos especificados.
 * @param {string[]} permissionsList
 * @returns {boolean}
 */
export function canAny(permissionsList = []) {
  if (!Array.isArray(permissionsList) || permissionsList.length === 0) return true;
  const ctx = getAuthContext();
  if (ctx.role === "admin") return true;
  return permissionsList.some((perm) => ctx.permissions.includes(perm));
}

/**
 * Verifica si el usuario autenticado posee TODOS los permisos especificados.
 * @param {string[]} permissionsList
 * @returns {boolean}
 */
export function canAll(permissionsList = []) {
  if (!Array.isArray(permissionsList) || permissionsList.length === 0) return true;
  const ctx = getAuthContext();
  if (ctx.role === "admin") return true;
  return permissionsList.every((perm) => ctx.permissions.includes(perm));
}
