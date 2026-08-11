import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.schemas.normalized_event import (
    NormalizedEvent,
    SchemaMeta,
    EventMeta,
    TenantMeta,
    HostMeta,
    ServiceMeta,
    SourceMeta,
    HttpMeta,
    EmailMeta,
)
from app.parsing.apache_access import ApacheAccessParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.maillog_dovecot import MaillogDovecotParser
from app.parsing.cpanel_access import CPanelAccessParser


def test_normalized_event_defaults():
    event = NormalizedEvent()
    assert event.sentinelx_schema.name == "sentinelx-ecs"
    assert event.sentinelx_schema.version == "1.0.0"
    assert event.tenant.id == "default"
    assert event.event.kind == "event"
    assert isinstance(event.timestamp_utc, datetime)
    assert event.timestamp_utc.tzinfo == timezone.utc


def test_normalized_event_to_opensearch_doc():
    event = NormalizedEvent(
        tenant=TenantMeta(id="tenant-acme"),
        source=SourceMeta(ip="1.2.3.4", port=443),
        http=HttpMeta(method="GET", status_code=200),
    )
    doc = event.to_opensearch_doc()
    assert doc["@timestamp"] is not None
    assert doc["tenant"]["id"] == "tenant-acme"
    assert doc["source"]["ip"] == "1.2.3.4"
    assert doc["http"]["method"] == "GET"
    assert doc["http"]["status_code"] == 200


def test_normalized_event_validation_errors():
    # Invalid HTTP status code (< 100)
    with pytest.raises(ValidationError):
        NormalizedEvent(http=HttpMeta(status_code=99))

    # Invalid port number (> 65535)
    with pytest.raises(ValidationError):
        NormalizedEvent(source=SourceMeta(port=70000))


def test_apache_parser_to_normalized_event():
    parser = ApacheAccessParser()
    line = '198.51.100.10 - - [09/Aug/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'
    norm = parser.parse_line_normalized(line, server="srv-web1", tenant_id="tenant-123")

    assert norm is not None
    assert isinstance(norm, NormalizedEvent)
    assert norm.tenant.id == "tenant-123"
    assert norm.host.name == "srv-web1"
    assert norm.source.ip == "198.51.100.10"
    assert norm.http.method == "POST"
    assert norm.http.status_code == 200
    assert norm.service.name == "http"


def test_exim_parser_to_normalized_event():
    parser = EximMainlogParser()
    line = '2026-08-09 12:00:00 1a2b3c-4d5e6f-7g <= sender@domain.com P=esmtpsa A=dovecot_login:authuser@domain.com H=(mail.remote.com) [198.51.100.20] S=2048'
    norm = parser.parse_line_normalized(line, server="srv-mail1", tenant_id="tenant-hosting")

    assert norm is not None
    assert norm.tenant.id == "tenant-hosting"
    assert norm.source.ip == "198.51.100.20"
    assert norm.email.authenticated_user == "dovecot_login:authuser@domain.com"
    assert norm.email.from_address == "sender@domain.com"


def test_dovecot_parser_to_normalized_event():
    parser = MaillogDovecotParser()
    line = 'Aug  9 12:00:00 mail dovecot[1234]: imap-login: Logged in: user=<user@domain.com>, method=PLAIN, rip=198.51.100.30, lip=10.0.0.1, mpid=1234, TLS'
    norm = parser.parse_line_normalized(line, server="srv-mail1")

    assert norm is not None
    assert norm.source.ip == "198.51.100.30"
    assert norm.user.name == "user@domain.com"
    assert norm.service.name == "imap/pop3"


def test_cpanel_parser_to_normalized_event():
    parser = CPanelAccessParser()
    line = '198.51.100.40 - cpaneluser [09/Aug/2026:12:00:00 -0000] "GET /cpsess123/frontend/index.html HTTP/1.1" 200 4500 "-" "Mozilla/5.0"'
    norm = parser.parse_line_normalized(line, server="srv-cpanel1")

    assert norm is not None
    assert norm.source.ip == "198.51.100.40"
    assert norm.user.name == "cpaneluser"
    assert norm.http.status_code == 200


def test_sar_stats_parser_numeric_metrics():
    from app.parsing.sar_stats import SarStatsParser
    parser = SarStatsParser()
    parser.parse_line("SAR_DATE=2026-08-11", server="srv-1")
    parser.parse_line("SAR_MODE=-q", server="srv-1")
    
    # sar -q line
    line_q = "09:00:01 AM       2      150      8.45      6.20      4.10         0"
    norm_q = parser.parse_line_normalized(line_q, server="srv-1")
    assert norm_q is not None
    assert isinstance(norm_q.metric.ldavg_1, float)
    assert norm_q.metric.ldavg_1 == 8.45
    assert norm_q.metric.ldavg_5 == 6.20
    assert norm_q.metric.runq_sz == 2.0

    # sar -r line
    parser.parse_line("SAR_MODE=-r", server="srv-1")
    line_r = "09:00:01 AM   4000000  12000000   8000000     66.67"
    norm_r = parser.parse_line_normalized(line_r, server="srv-1")
    assert norm_r is not None
    assert isinstance(norm_r.metric.mem_used_pct, float)
    assert norm_r.metric.mem_used_pct == 66.67
    assert norm_r.metric.kb_mem_free == 4000000

    # sar -d line
    parser.parse_line("SAR_MODE=-d", server="srv-1")
    line_d = "09:00:01 AM       dev10-0    120.50      85.4"
    norm_d = parser.parse_line_normalized(line_d, server="srv-1")
    assert norm_d is not None
    assert norm_d.metric.device == "dev10-0"
    assert norm_d.metric.tps == 120.50
    assert norm_d.metric.util_pct == 85.4


def test_private_ip_scope_no_prv_country_code():
    from app.parsing.apache_access import ApacheAccessParser
    from app.enrichment.geoip_enricher import enrich_ip_into_extra

    parser = ApacheAccessParser()
    line = '192.168.1.50 - - [09/Aug/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 500 "-" "Mozilla"'
    pe = parser.parse_line(line, server="srv-local")
    assert pe is not None
    pe.extra = enrich_ip_into_extra(ip=pe.ip_client, extra=pe.extra)
    norm = pe.to_normalized_event()

    assert norm.source.ip == "192.168.1.50"
    assert norm.source.geo_country_iso_code is None
    assert norm.labels.get("ip_scope") == "private"


def test_exim_parser_multi_formats():
    parser = EximMainlogParser()

    # 1. Inbound <=
    l_inbound = '2026-08-11 10:00:00 1a2b3c-4d5e6f-7g <= sender@domain.com H=mail.remote.com [198.51.100.25] P=esmtps S=1500'
    norm_in = parser.parse_line_normalized(l_inbound, server="srv-mail")
    assert norm_in is not None
    assert norm_in.email.from_address == "sender@domain.com"
    assert norm_in.source.ip == "198.51.100.25"

    # 2. Outbound =>
    l_outbound = '2026-08-11 10:01:00 1a2b3c-4d5e6f-7g => rcpt@target.com H=mail.target.com [198.51.100.35] C="250 OK"'
    norm_out = parser.parse_line_normalized(l_outbound, server="srv-mail")
    assert norm_out is not None
    assert norm_out.email.to_address == "rcpt@target.com"
    assert norm_out.event.outcome == "success"

    # 3. Auth Failed
    l_auth_fail = '2026-08-11 10:02:00 dovecot_login authenticator failed for (user) [198.51.100.45]: 535 Incorrect authentication data'
    norm_af = parser.parse_line_normalized(l_auth_fail, server="srv-mail")
    assert norm_af is not None
    assert norm_af.source.ip == "198.51.100.45"
    assert norm_af.event.outcome == "failure"


def test_secure_ssh_parser_formats():
    from app.parsing.system_secure import SecureLogParser
    parser = SecureLogParser()

    # SSH Auth Fail
    l_fail = "Aug 11 10:00:00 srv-ssh sshd[1234]: Failed password for root from 198.51.100.88 port 54321 ssh2"
    norm_f = parser.parse_line_normalized(l_fail, server="srv-ssh")
    assert norm_f is not None
    assert norm_f.source.ip == "198.51.100.88"
    assert norm_f.source.port == 54321
    assert norm_f.user.name == "root"
    assert norm_f.event.outcome == "failure"

    # SSH Auth Accept
    l_ok = "Aug 11 10:05:00 srv-ssh sshd[1235]: Accepted password for adminuser from 198.51.100.88 port 54322 ssh2"
    norm_ok = parser.parse_line_normalized(l_ok, server="srv-ssh")
    assert norm_ok is not None
    assert norm_ok.source.ip == "198.51.100.88"
    assert norm_ok.user.name == "adminuser"
    assert norm_ok.event.outcome == "success"


def test_modsec_audit_parser():
    from app.parsing.modsec_audit import ModSecAuditParser
    parser = ModSecAuditParser()

    lines = [
        "--12345678-A--",
        "[11/Aug/2026:10:00:00 +0000] txid123 198.51.100.99 12345 10.0.0.1 80",
        "--12345678-B--",
        "POST /wp-login.php HTTP/1.1",
        "Host: example.com",
        "--12345678-F--",
        "HTTP/1.1 403 Forbidden",
        "--12345678-H--",
        'Message: Warning. Pattern match "SELECT" at ARGS:user. [id "942100"] [msg "SQLi Detected"]',
        "--12345678-Z--",
    ]
    norm = None
    for l in lines:
        pe = parser.parse_line(l, server="srv-waf")
        if pe:
            norm = pe.to_normalized_event()

    assert norm is not None
    assert norm.source.ip == "198.51.100.99"
    assert norm.http.method == "POST"


def test_lfd_log_parser():
    from app.parsing.lfd_log import LfdLogParser
    parser = LfdLogParser()

    line = "Aug 11 10:00:00 srv-lfd lfd[999]: (sshd) Failed SSH login from 198.51.100.77 (US/United States/198.51.100.77): 5 in the last 300 secs - *Blocked in iptables*"
    norm = parser.parse_line_normalized(line, server="srv-lfd")
    assert norm is not None
    assert norm.source.ip == "198.51.100.77"


def test_filemanager_parser():
    from app.parsing.filemanager import FileManagerParser
    parser = FileManagerParser()

    line = '2026-08-11 10:00:00 user=cpaneluser ip=198.51.100.66 action=upload path=/public_html/shell.php size=2048'
    norm = parser.parse_line_normalized(line, server="srv-panel")
    assert norm is not None
    assert norm.user.name == "cpaneluser"
    assert norm.file.path == "/public_html/shell.php"
    assert norm.source.ip == "198.51.100.66"

