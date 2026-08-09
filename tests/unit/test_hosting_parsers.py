import pytest
from app.parsing.imunify360 import Imunify360Parser
from app.parsing.auditd_log import AuditdParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.maillog_dovecot import MaillogDovecotParser
from app.parsing.lfd_log import LfdLogParser


def test_imunify360_parser_malware_hit():
    parser = Imunify360Parser()
    line = "2026-08-09 12:30:00 [ERROR] [malware] file=/home/user/public_html/c99.php scan_id=s123 threat=WSO.Webshell user=user1"
    evt = parser.parse_line(line, "srv1")
    assert evt is not None
    assert evt.service == "IMUNIFY360"
    assert evt.extra["threat"] == "WSO.Webshell"
    assert evt.extra["file"]["path"] == "/home/user/public_html/c99.php"


def test_auditd_parser_execve():
    parser = AuditdParser()
    line = 'type=EXECVE msg=audit(1723220000.123:456): argc=2 a0="nc" a1="-e" exe="/usr/bin/nc" sauid=0 hostname=srv2'
    evt = parser.parse_line(line, "srv2")
    assert evt is not None
    assert evt.service == "AUDITD"
    assert evt.extra["process"]["path"] == "/usr/bin/nc"
    assert evt.extra["audit_type"] == "EXECVE"


def test_lfd_parser_block():
    parser = LfdLogParser()
    line = "Aug  9 12:00:00 srv1 lfd[1234]: (sshd) Failed SSH login from 198.51.100.99 (US/United States/host.com): 5 in the last 300 secs - *Blocked in csf*"
    evt = parser.parse_line(line, "srv1")
    assert evt is not None
    assert evt.ip_client == "198.51.100.99"
