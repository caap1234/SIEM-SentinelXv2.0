import pytest
from datetime import datetime, timezone
from app.parsing.system_secure import SecureLogParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.sar_stats import SarStatsParser
from app.parsing.modsec_audit import ModSecAuditParser
from app.parsing.apache_access import ApacheAccessParser
from app.services.rule_engine_v2 import RuleEngineV2, _safe_eval, _get_from_event


def test_rule_engine_sar_high_load_expression_compatibility():
    parser = SarStatsParser()
    parser.parse_line("SAR_DATE=2026-08-11", server="srv-1")
    parser.parse_line("SAR_MODE=-q", server="srv-1")
    
    line_q = "09:00:01 AM       2      150      9.50      7.20      5.10         0"
    norm = parser.parse_line_normalized(line_q, server="srv-1")
    assert norm is not None

    # Context derived by RuleEngineV2
    ctx = {
        "ld1": norm.metric.ldavg_1,
        "ld5": norm.metric.ldavg_5,
        "runq": norm.metric.runq_sz,
        "count": 5,
    }
    
    # Rule condition in RES-001
    condition = "(count >= 5) and (ld1 >= 6.0) and (ld5 >= 6.0)"
    assert _safe_eval(condition, ctx) is True


def test_rule_engine_sar_high_memory_expression_compatibility():
    parser = SarStatsParser()
    parser.parse_line("SAR_DATE=2026-08-11", server="srv-1")
    parser.parse_line("SAR_MODE=-r", server="srv-1")

    line_r = "09:00:01 AM   1000000  15000000  14000000     93.50"
    norm = parser.parse_line_normalized(line_r, server="srv-1")
    assert norm is not None

    ctx = {
        "mem_pct": norm.metric.mem_used_pct,
        "count": 5,
    }

    # Rule condition in RES-003
    condition = "(count >= 5) and (mem_pct >= 92.0)"
    assert _safe_eval(condition, ctx) is True


def test_rule_engine_ssh_brute_force_compatibility():
    parser = SecureLogParser()
    line = "Aug 11 10:00:00 srv-ssh sshd[1234]: Failed password for root from 198.51.100.88 port 54321 ssh2"
    norm = parser.parse_line_normalized(line, server="srv-ssh")
    assert norm is not None
    assert norm.source.ip == "198.51.100.88"
    assert norm.event.outcome == "failure"

    ctx = {
        "count": 6,
        "ip": norm.source.ip,
    }
    condition = "(count >= 5)"
    assert _safe_eval(condition, ctx) is True


def test_rule_engine_exim_auth_abuse_compatibility():
    parser = EximMainlogParser()
    line = '2026-08-11 10:02:00 dovecot_login authenticator failed for (user) [198.51.100.45]: 535 Incorrect authentication data'
    norm = parser.parse_line_normalized(line, server="srv-mail")
    assert norm is not None
    assert norm.source.ip == "198.51.100.45"
    assert norm.event.outcome == "failure"
    assert norm.event.action in ("fail", "auth_login", "smtp", "mail_flow")
