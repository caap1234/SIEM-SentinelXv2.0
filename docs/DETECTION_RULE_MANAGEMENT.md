# Gestión de Reglas de Detección del Motor de Correlación

## 1. Visión General

El módulo de **Reglas de Detección** (`/dashboard/reglas`) permite a los administradores del SOC afinar los umbrales (`threshold`), ventanas temporales (`window_seconds`), severidad y estado (`enabled`) del **CorrelationEngine**.

---

## 2. Ajuste Fino de Reglas y Auditoría

Cada regla define criterios de correlación in-memory en ventanas deslizantes. Los administradores pueden ajustar parámetros clave sin necesidad de reiniciar el servicio ni modificar código:
- **`enabled`**: Activa o desactiva la evaluación de la regla.
- **`threshold`**: Número mínimo de eventos requeridos dentro de la ventana para disparar la alerta.
- **`window_seconds`**: Ventana temporal en segundos (ej. 300s = 5 minutos).
- **`severity`**: Nivel de severidad asignado a las alertas (`info`, `low`, `medium`, `high`, `critical`).

> **REGLA DE SEGURIDAD**: Todo cambio en las reglas queda registrado en la tabla `audit_logs` en PostgreSQL con el evento `RULE_UPDATE`, detallando el usuario, timestamp, valor anterior y nuevo.
