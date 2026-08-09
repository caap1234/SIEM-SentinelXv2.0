# app/parsing/imunify360.py
"""
Parser especializado para logs de Imunify360 / ImunifyAV+.
Normaliza detecciones de malware, bloqueos WAF, escaneos de archivos y cambios de reputación IP.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent
from app.core.timeutils import parse_any_timestamp_to_utc

IMUNIFY_LOG_RE = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>INFO|WARN|WARNING|ERROR|CRITICAL)\]\s+\[(?P<module>malware|waf|proactive|ip_reputation)\]\s+(?P<msg>.*)$',
    re.IGNORECASE,
)

MALWARE_HIT_RE = re.compile(
    r'(?:file|path)=(?P<path>[^\s]+)\s+scan_id=(?P<scan_id>[^\s]+)\s+threat=(?P<threat>[^\s]+)(?:\s+user=(?P<user>[^\s]+))?',
    re.IGNORECASE,
)

IP_BLOCK_RE = re.compile(
    r'(?:blocked|blacklisted)\s+ip=(?P<ip>[0-9a-fA-F:\.]+)(?:\s+reason=(?P<reason>.*))?',
    re.IGNORECASE,
)


class Imunify360Parser(LogParser):
    source = "IMUNIFY360"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        line = (line or "").strip()
        if not line:
            return None

        m = IMUNIFY_LOG_RE.match(line)
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        level = (m.group("level") or "INFO").upper()
        mod = (m.group("module") or "malware").lower()
        msg = (m.group("msg") or "").strip()

        ip_client = None
        user = None
        file_path = None
        threat_name = None

        m_mal = MALWARE_HIT_RE.search(msg)
        if m_mal:
            file_path = m_mal.group("path")
            threat_name = m_mal.group("threat")
            user = m_mal.group("user")

        m_ip = IP_BLOCK_RE.search(msg)
        if m_ip:
            ip_client = m_ip.group("ip")

        severity = 70 if level in ("ERROR", "CRITICAL") else 40

        extra = {
            "event_type": f"imunify360_{mod}",
            "severity": severity,
            "module": mod,
            "level": level,
            "threat": threat_name,
            "file": {"path": file_path, "name": file_path.split("/")[-1] if file_path else None},
            "user": user,
            "source_ip": ip_client,
        }

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="IMUNIFY360",
            ip_client=ip_client,
            username=user,
            message=f"IMUNIFY360 [{mod.upper()}] {msg}",
            extra=extra,
            log_upload_id=log_upload_id,
        )
