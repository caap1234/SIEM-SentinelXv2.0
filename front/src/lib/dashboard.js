/**
 * SentinelX SIEM - Capa de Servicio API para Dashboard SOC en Tiempo Real
 */

import { apiGet } from "./api.js";

/**
 * Obtiene el resumen ejecutivo de estado del clúster SIEM y contadores de eventos/alertas.
 * @returns {Promise<{
 *   events_received: number,
 *   events_processed: number,
 *   events_indexed: number,
 *   alerts_active: number,
 *   incidents_open: number,
 *   agents_online: number,
 *   tenant_id: string,
 *   system_health: { api: string, nats: string, opensearch: string, minio: string, postgresql: string }
 * }>}
 */
export async function getDashboardSummary() {
  return apiGet("/api/v1/dashboard/summary");
}

/**
 * Obtiene la serie temporal de actividad de eventos (últimas 24h).
 * @returns {Promise<{ tenant_id: string, series: Array<{ timestamp: string, events: number, alerts: number }> }>}
 */
export async function getDashboardActivity() {
  return apiGet("/api/v1/dashboard/activity");
}

/**
 * Obtiene las alertas críticas recientes disparadas por el motor de correlación de hosting.
 * @returns {Promise<{ items: Array<{ id: number|string, title: string, description: string, severity: string, status: string, tenant_id: string, created_at: string }> }>}
 */
export async function getRecentAlerts() {
  return apiGet("/api/v1/dashboard/alerts/recent");
}

/**
 * Obtiene el estado de salud, heartbeat y spool de los agentes Linux registrados.
 * @returns {Promise<{ tenant_id: string, agents: Array<{ hostname: string, status: string, version: string, last_heartbeat: string, cpu_percent: number, memory_percent: number, spool_events: number }> }>}
 */
export async function getAgentsStatus() {
  return apiGet("/api/v1/dashboard/agents/status");
}
