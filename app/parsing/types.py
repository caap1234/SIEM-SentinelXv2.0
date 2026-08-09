# app/parsing/types.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from app.schemas.normalized_event import (
    NormalizedEvent,
    EventMeta,
    TenantMeta,
    HostMeta,
    ServiceMeta,
    SourceMeta,
    DestinationMeta,
    UserMeta,
    HttpMeta,
    EmailMeta,
    FileMeta,
    ProcessMeta,
    RuleMeta,
    LogMeta,
    HostingContext,
)


@dataclass
class ParsedEvent:
    timestamp_utc: datetime
    server: str
    source: str
    service: str
    message: str

    ip_client: Optional[str] = None
    ip_server: Optional[str] = None
    domain: Optional[str] = None
    username: Optional[str] = None

    extra: Dict[str, Any] = field(default_factory=dict)

    log_upload_id: Optional[int] = None
    raw_id: Optional[int] = None

    def to_orm_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "server": self.server,
            "source": self.source,
            "service": self.service,
            "ip_client": self.ip_client,
            "ip_server": self.ip_server,
            "domain": self.domain,
            "username": self.username,
            "message": self.message,
            "extra": self.extra or {},
            "log_upload_id": self.log_upload_id,
            "raw_id": self.raw_id,
        }

    def to_normalized_event(self, tenant_id: str = "default") -> NormalizedEvent:
        """Convierte ParsedEvent al esquema canónico NormalizedEvent (ECS-compliant)."""
        extra = self.extra or {}
        http_data = extra.get("http") if isinstance(extra, dict) else {}
        if not isinstance(http_data, dict):
            http_data = {}

        panel_data = extra.get("panel") if isinstance(extra, dict) else {}
        if not isinstance(panel_data, dict):
            panel_data = {}

        email_data = extra.get("email") if isinstance(extra, dict) else {}
        if not isinstance(email_data, dict):
            email_data = {}

        file_data = extra.get("file") if isinstance(extra, dict) else {}
        if not isinstance(file_data, dict):
            file_data = {}

        proc_data = extra.get("process") if isinstance(extra, dict) else {}
        if not isinstance(proc_data, dict):
            proc_data = {}

        rule_data = extra.get("rule") if isinstance(extra, dict) else {}
        if not isinstance(rule_data, dict):
            rule_data = {}

        user_name = (
            self.username
            or extra.get("user")
            or extra.get("authenticated_user")
            or panel_data.get("cpanel_user")
        )

        http_method = http_data.get("method") or panel_data.get("http_method")
        http_status = http_data.get("status") or panel_data.get("status_code")

        return NormalizedEvent(
            timestamp_utc=self.timestamp_utc,
            tenant=TenantMeta(id=tenant_id),
            event=EventMeta(
                dataset=self.source.lower(),
                action=extra.get("action") or extra.get("event_type") or self.service.lower(),
                outcome=extra.get("outcome", "success" if not extra.get("error") else "failure"),
                severity=int(extra.get("severity", 1)),
                original=self.message,
            ),
            host=HostMeta(
                name=self.server,
                hostname=self.server,
            ),
            service=ServiceMeta(
                name=self.service.lower(),
            ),
            source=SourceMeta(
                ip=self.ip_client or extra.get("source_ip"),
                port=extra.get("source_port"),
                geo_country_iso_code=extra.get("country_iso"),
            ),
            destination=DestinationMeta(
                ip=self.ip_server,
                port=extra.get("destination_port"),
            ),
            user=UserMeta(
                name=user_name,
            ),
            customer=HostingContext(
                domain_name=self.domain or http_data.get("host"),
            ),
            http=HttpMeta(
                method=http_method,
                status_code=http_status,
                referrer=http_data.get("referer"),
            ),
            email=EmailMeta(
                from_address=email_data.get("from") or extra.get("mail_from"),
                to_address=email_data.get("to") or extra.get("rcpt"),
                subject=email_data.get("subject"),
                queue_id=email_data.get("queue_id") or extra.get("exim_id"),
                authenticated_user=email_data.get("auth_user") or self.username,
            ),
            file=FileMeta(
                path=file_data.get("path"),
                name=file_data.get("name"),
                hash_sha256=file_data.get("sha256"),
            ),
            process=ProcessMeta(
                pid=proc_data.get("pid"),
                name=proc_data.get("name"),
                executable=proc_data.get("path"),
            ),
            rule=RuleMeta(
                id=rule_data.get("id"),
                name=rule_data.get("name"),
            ),
            log=LogMeta(
                original=self.message,
            ),
        )
