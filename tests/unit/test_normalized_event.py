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
    assert event.schema.name == "sentinelx-ecs"
    assert event.schema.version == "1.0.0"
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
