import pytest
from app.parsing.apache_access import ApacheAccessParser
from app.parsing.apache_error_log import ApacheErrorLogParser
from app.parsing.nginx_access import NginxAccessParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.maillog_dovecot import MaillogDovecotParser
from app.parsing.modsec_audit import ModSecAuditParser
from app.parsing.lfd_log import LfdLogParser
from app.parsing.system_secure import SecureLogParser
from app.parsing.cpanel_access import CPanelAccessParser
from app.parsing.wp_error_log import WpErrorLogParser

def test_apache_access_parser():
    parser = ApacheAccessParser()
    line = '192.168.1.50 - - [09/Aug/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 4500 "https://example.com/" "Mozilla/5.0"'
    event = parser.parse_line(line, server="srv1", log_upload_id=10)
    assert event is not None
    assert event.ip_client == "192.168.1.50"
    assert event.extra["http"]["status"] == 200
    assert event.extra["http"]["method"] == "GET"
    assert event.server == "srv1"

def test_nginx_access_parser():
    parser = NginxAccessParser()
    line = '203.0.113.195 - - [09/Aug/2026:12:05:00 +0000] "POST /xmlrpc.php HTTP/1.1" 403 162 "-" "curl/7.68.0"'
    event = parser.parse_line(line, server="srv2", log_upload_id=11)
    assert event is not None
    assert event.ip_client == "203.0.113.195"
    assert event.extra["http"]["status"] == 403
    assert event.extra["http"]["method"] == "POST"

def test_exim_mainlog_parser():
    parser = EximMainlogParser()
    line = '2026-08-09 12:00:00 1a2b3c-4d5e6f-7g <= user@example.com P=esmtpsa A=dovecot_login:user@example.com H=(mail.remote.com) [198.51.100.25] S=1540'
    event = parser.parse_line(line, server="mail1", log_upload_id=12)
    assert event is not None
    assert event.ip_client == "198.51.100.25"

def test_dovecot_maillog_parser():
    parser = MaillogDovecotParser()
    line = 'Aug  9 12:00:00 mail dovecot[1234]: imap-login: Logged in: user=<info@domain.com>, method=PLAIN, rip=198.51.100.50, lip=192.168.1.2, mpid=1234, TLS'
    event = parser.parse_line(line, server="mail1", log_upload_id=13)
    assert event is not None
    assert event.ip_client == "198.51.100.50"

def test_lfd_log_parser():
    parser = LfdLogParser()
    line = 'Aug  9 12:00:00 srv1 lfd[1234]: (sshd) Failed SSH login from 198.51.100.99 (US/United States/host.example.com): 5 in the last 300 secs - *Blocked in csf*'
    event = parser.parse_line(line, server="srv1", log_upload_id=14)
    assert event is not None
    assert event.ip_client == "198.51.100.99"

def test_secure_log_parser():
    parser = SecureLogParser()
    line = 'Aug  9 12:00:00 srv1 sshd[5678]: Failed password for root from 198.51.100.88 port 54321 ssh2'
    event = parser.parse_line(line, server="srv1", log_upload_id=15)
    assert event is not None
    assert event.ip_client == "198.51.100.88"

def test_cpanel_access_parser():
    parser = CPanelAccessParser()
    line = '198.51.100.77 - myuser [09/Aug/2026:12:00:00 -0000] "GET /cpsess1234567890/frontend/paper_lantern/index.html HTTP/1.1" 200 8500 "https://srv1.example.com:2083/" "Mozilla/5.0"'
    event = parser.parse_line(line, server="srv1", log_upload_id=16)
    assert event is not None
    assert event.ip_client == "198.51.100.77"
    assert event.username == "myuser"

def test_wp_error_log_parser():
    parser = WpErrorLogParser()
    line = '[09-Aug-2026 12:00:00 UTC] PHP Fatal error: Uncaught Error: Call to undefined function eval_bad() in /home/user/public_html/wp-content/plugins/bad/bad.php on line 15'
    event = parser.parse_line(line, server="srv1", log_upload_id=17)
    assert event is not None
