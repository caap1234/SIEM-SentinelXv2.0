# app/parsing/auditd_log.py
"""
Parser especializado para logs de Linux auditd (Security Auditing Subsystem).
Normaliza eventos de execve, privilege escalation, syscalls, modificación de archivos de sistema y autenticación.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent
from app.core.timeutils import parse_any_timestamp_to_utc

AUDIT_LOG_RE = re.compile(
    r'^type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<epoch>\d+\.\d+):\d+\):\s+(?P<msg>.*)$',
    re.IGNORECASE,
)

EXECVE_RE = re.compile(r'exe="(?P<exe>[^"]+)"\s+sauid=(?P<sauid>\d+)?.*hostname=(?P<host>[^\s]+)?', re.IGNORECASE)
SYSCALL_RE = re.compile(r'arch=(?P<arch>[^\s]+)\s+syscall=(?P<syscall>\d+)\s+success=(?P<success>yes|no)\s+exit=(?P<exit>-?\d+)', re.IGNORECASE)
USER_ACCT_RE = re.compile(r'acct="(?P<user>[^"]+)"\s+exe="(?P<exe>[^"]+)"\s+hostname=(?P<host>[^\s]+)\s+addr=(?P<addr>[^\s]+)?', re.IGNORECASE)


class AuditdParser(LogParser):
    source = "AUDITD"

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

        m = AUDIT_LOG_RE.match(line)
        if not m:
            return None

        audit_type = (m.group("type") or "SYSCALL").upper()
        epoch_str = m.group("epoch") or ""
        msg = (m.group("msg") or "").strip()

        try:
            epoch_sec = float(epoch_str)
            ts = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        exe_path = None
        user_name = None
        ip_client = None
        syscall_num = None
        outcome = "success"

        m_exec = EXECVE_RE.search(msg)
        if m_exec:
            exe_path = m_exec.group("exe")

        m_sys = SYSCALL_RE.search(msg)
        if m_sys:
            syscall_num = m_sys.group("syscall")
            outcome = "success" if m_sys.group("success") == "yes" else "failure"

        m_usr = USER_ACCT_RE.search(msg)
        if m_usr:
            user_name = m_usr.group("user")
            ip_client = m_usr.group("addr")
            if ip_client in ("?", "unset", "(null)"):
                ip_client = None

        extra = {
            "event_type": f"auditd_{audit_type.lower()}",
            "audit_type": audit_type,
            "outcome": outcome,
            "syscall": syscall_num,
            "process": {"path": exe_path, "name": exe_path.split("/")[-1] if exe_path else None},
            "user": user_name,
            "source_ip": ip_client,
        }

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="AUDITD",
            ip_client=ip_client,
            username=user_name,
            message=f"AUDITD [{audit_type}] {msg}",
            extra=extra,
            log_upload_id=log_upload_id,
        )
