# app/parsing/base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.parsing.types import ParsedEvent
from app.schemas.normalized_event import NormalizedEvent


class LogParser(ABC):
    source: str

    @abstractmethod
    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        raise NotImplementedError

    def parse_line_normalized(
        self,
        line: str,
        server: str,
        *,
        tenant_id: str = "default",
        log_upload_id: Optional[int] = None,
    ) -> Optional[NormalizedEvent]:
        """Convierte una línea directamente al objeto canónico NormalizedEvent."""
        pe = self.parse_line(line, server, log_upload_id=log_upload_id)
        if not pe:
            return None
        return pe.to_normalized_event(tenant_id=tenant_id)
