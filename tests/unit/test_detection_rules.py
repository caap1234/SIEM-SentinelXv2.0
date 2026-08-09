import pytest
from app.schemas.detection_rule import DetectionRule
from app.core.hosting_rules import DEFAULT_HOSTING_RULES


def test_detection_rule_matches_exact_condition():
    rule = DetectionRule(
        id="R1",
        name="Test Rule",
        description="Test",
        event_conditions={"service.name": "exim", "event.action": "auth_failed"},
    )

    doc_match = {"service": {"name": "exim"}, "event": {"action": "auth_failed"}}
    doc_no_match = {"service": {"name": "exim"}, "event": {"action": "email_sent"}}

    assert rule.matches_event(doc_match) is True
    assert rule.matches_event(doc_no_match) is False


def test_detection_rule_matches_contains_condition():
    rule = DetectionRule(
        id="R2",
        name="WP Login Rule",
        description="Test",
        event_conditions={"url.path": "contains:wp-login.php"},
    )

    doc_match = {"url": {"path": "/site/wp-login.php?action=login"}}
    doc_no_match = {"url": {"path": "/index.php"}}

    assert rule.matches_event(doc_match) is True
    assert rule.matches_event(doc_no_match) is False


def test_detection_rule_group_key_generation():
    rule = DetectionRule(
        id="R3",
        name="Group Key Rule",
        description="Test",
        group_by=["source.ip", "user.name"],
    )

    doc = {"source": {"ip": "198.51.100.5"}, "user": {"name": "admin"}}
    assert rule.get_group_key(doc) == "198.51.100.5:admin"


def test_default_hosting_rules_populated():
    rule_ids = [r.id for r in DEFAULT_HOSTING_RULES]
    assert "RULE_MAIL_SMTP_AUTH_BRUTEFORCE" in rule_ids
    assert "RULE_WEB_WP_LOGIN_BRUTEFORCE" in rule_ids
    assert "RULE_WEB_WEBSHELL_DETECTED" in rule_ids
    assert "RULE_SYS_SSH_BRUTEFORCE" in rule_ids
    assert "RULE_NET_CSF_LFD_BLOCK" in rule_ids
