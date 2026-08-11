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
    MetricMeta,
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
        if not isinstance(http_data, dict) or not http_data:
            waf_data = extra.get("waf") if isinstance(extra, dict) else {}
            if isinstance(waf_data, dict) and isinstance(waf_data.get("http"), dict):
                http_data = waf_data["http"]
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

        geo_data = extra.get("geo") if isinstance(extra, dict) else {}
        if not isinstance(geo_data, dict):
            geo_data = extra.get("geoip") if isinstance(extra, dict) else {}
        if not isinstance(geo_data, dict):
            geo_data = {}

        asn_data = extra.get("asn") if isinstance(extra, dict) else {}
        if not isinstance(asn_data, dict):
            asn_data = {}
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

        # GeoIP ISO Code handling: Nunca usar "PRV" o "UNK" como código ISO de país
        country_code = geo_data.get("country_code") or extra.get("country_iso")
        is_private = bool(geo_data.get("is_private") or extra.get("is_private") or (country_code == "PRV"))
        geo_country_iso = None if is_private or country_code in ("PRV", "UNK") else country_code

        labels_map: Dict[str, str] = {}
        if is_private:
            labels_map["ip_scope"] = "private"

        # Métricas numéricas tipadas (SAR)
        metric_meta = None
        if isinstance(extra, dict) and isinstance(extra.get("metric"), dict):
            m = extra["metric"]
            metric_meta = MetricMeta(
                family=m.get("family"),
                name=m.get("name"),
                cpu_count=int(m["cpu_count"]) if m.get("cpu_count") is not None else None,
                runq_sz=float(m["runq_sz"]) if m.get("runq_sz") is not None else None,
                plist_sz=float(m["plist_sz"]) if m.get("plist_sz") is not None else None,
                blocked=float(m["blocked"]) if m.get("blocked") is not None else None,
                ldavg_1=float(m["ldavg_1"]) if m.get("ldavg_1") is not None else None,
                ldavg_5=float(m["ldavg_5"]) if m.get("ldavg_5") is not None else None,
                ldavg_15=float(m["ldavg_15"]) if m.get("ldavg_15") is not None else None,
                ldavg_1_per_cpu=float(m["ldavg_1_per_cpu"]) if m.get("ldavg_1_per_cpu") is not None else None,
                ldavg_5_per_cpu=float(m["ldavg_5_per_cpu"]) if m.get("ldavg_5_per_cpu") is not None else None,
                ldavg_15_per_cpu=float(m["ldavg_15_per_cpu"]) if m.get("ldavg_15_per_cpu") is not None else None,
                kb_mem_free=int(m["kb_mem_free"]) if m.get("kb_mem_free") is not None else None,
                kb_mem_used=int(m["kb_mem_used"]) if m.get("kb_mem_used") is not None else None,
                kb_mem_avail=int(m["kb_mem_avail"]) if m.get("kb_mem_avail") is not None else None,
                mem_used_pct=float(m["mem_used_pct"]) if m.get("mem_used_pct") is not None else None,
                device=str(m["device"]) if m.get("device") is not None else None,
                tps=float(m["tps"]) if m.get("tps") is not None else None,
                util_pct=float(m["util_pct"]) if m.get("util_pct") is not None else None,
            )
            for mk, mv in m.items():
                if mv is not None:
                    labels_map[str(mk)] = str(mv)

        src_port = extra.get("source_port") or extra.get("port")
        try:
            src_port_int = int(src_port) if src_port is not None else None
        except (ValueError, TypeError):
            src_port_int = None

        # Derive event outcome cleanly
        def _derive_outcome(e_dict: Dict[str, Any]) -> str:
            if e_dict.get("outcome"):
                return str(e_dict["outcome"])
            act = e_dict.get("action")
            if (
                act in ("fail", "failure", "deny", "block")
                or (act in ("auth_login", "auth_sudo", "login") and e_dict.get("auth_success") is False)
                or e_dict.get("error")
            ):
                return "failure"
            return "success"

        return NormalizedEvent(
            timestamp_utc=self.timestamp_utc,
            tenant=TenantMeta(id=tenant_id),
            event=EventMeta(
                dataset=self.source.lower(),
                action=extra.get("action") or extra.get("event_type") or self.service.lower(),
                outcome=_derive_outcome(extra),
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
                port=src_port_int,
                geo_country_iso_code=geo_country_iso,
                as_number=asn_data.get("number"),
                as_organization_name=asn_data.get("org") or asn_data.get("organization"),
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
                from_address=email_data.get("from") or extra.get("mail_from") or extra.get("from") or extra.get("sender"),
                to_address=email_data.get("to") or extra.get("rcpt") or extra.get("to") or extra.get("recipient"),
                subject=email_data.get("subject") or extra.get("subject"),
                queue_id=email_data.get("queue_id") or extra.get("exim_id") or extra.get("msgid"),
                authenticated_user=email_data.get("auth_user") or extra.get("auth_user") or self.username,
            ),
            file=FileMeta(
                path=file_data.get("path"),
                name=file_data.get("name"),
                hash_sha256=file_data.get("sha256"),
            ),
            labels=labels_map,
            metric=metric_meta or MetricMeta(),
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
