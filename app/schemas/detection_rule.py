# app/schemas/detection_rule.py
"""
Esquema Pydantic v2 para Reglas de Detección en Tiempo Real de SentinelX SIEM.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DetectionRule(BaseModel):
    id: str = Field(..., description="ID único de la regla de detección")
    tenant_id: str = Field(default="default", description="Identificador del tenant asociado")
    name: str = Field(..., description="Nombre de la regla")
    description: str = Field(..., description="Descripción técnica de la amenaza detectada")
    category: str = Field(default="threat", description="Categoría (mail, web, system, network)")
    severity: int = Field(default=50, ge=1, le=100, description="Nivel de severidad de 1 a 100")
    risk_score: float = Field(default=50.0, description="Puntuación de riesgo asociativa")

    # Condiciones de emparejamiento con NormalizedEvent
    event_conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Filtro clave-valor sobre el evento canónico (ej. {'service.name': 'exim', 'event.action': 'auth_failed'})",
    )
    group_by: List[str] = Field(
        default_factory=lambda: ["source.ip"],
        description="Campos de agrupación para la ventana temporal (ej. ['source.ip'] o ['user.name'])",
    )

    threshold: int = Field(default=10, ge=1, description="Número de coincidencias requeridas para disparar la alerta")
    time_window_seconds: int = Field(default=300, ge=1, description="Ventana de tiempo deslizante en segundos")
    enabled: bool = Field(default=True, description="Estado activo/inactivo de la regla")

    def matches_event(self, event_doc: Dict[str, Any]) -> bool:
        """
        Evalúa si un evento en diccionario cumple las condiciones de event_conditions.
        """
        if not self.enabled:
            return False

        for path, expected in self.event_conditions.items():
            val = self._extract_nested_value(event_doc, path)
            if isinstance(expected, list):
                if val not in expected:
                    return False
            elif isinstance(expected, str) and expected.startswith("contains:"):
                substr = expected[len("contains:"):]
                if not val or substr.lower() not in str(val).lower():
                    return False
            else:
                if val != expected:
                    return False
        return True

    def get_group_key(self, event_doc: Dict[str, Any]) -> str:
        """
        Genera la clave única de agrupación para la ventana de tiempo.
        """
        parts = []
        for field in self.group_by:
            val = self._extract_nested_value(event_doc, field) or "unknown"
            parts.append(str(val))
        return ":".join(parts)

    @staticmethod
    def _extract_nested_value(doc: Dict[str, Any], path: str) -> Any:
        """Helper para extraer campos anidados estilo dot-notation (ej. 'source.ip')."""
        keys = path.split(".")
        curr: Any = doc
        for k in keys:
            if isinstance(curr, dict):
                curr = curr.get(k)
            else:
                return None
        return curr
