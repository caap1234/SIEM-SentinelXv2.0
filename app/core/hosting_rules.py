# app/core/hosting_rules.py
"""
Reglas predeterminadas de detección de amenazas para entornos de hosting masivo (cPanel, Exim, Dovecot, ModSec, CSF).
"""
from __future__ import annotations

from typing import List
from app.schemas.detection_rule import DetectionRule

DEFAULT_HOSTING_RULES: List[DetectionRule] = [
    # ── Correo Electronico ──────────────────────────────────────────────────
    DetectionRule(
        id="RULE_MAIL_SMTP_AUTH_BRUTEFORCE",
        tenant_id="default",
        name="Ataque de Fuerza Bruta SMTP AUTH (Exim)",
        description="Detección de más de 50 fallos de autenticación SMTP AUTH desde la misma IP de origen.",
        category="mail",
        severity=75,
        risk_score=80.0,
        event_conditions={
            "service.name": "exim",
            "event.action": "auth_failed",
        },
        group_by=["source.ip"],
        threshold=50,
        time_window_seconds=300,
    ),
    DetectionRule(
        id="RULE_MAIL_HIGH_OUTBOUND_SPAM",
        tenant_id="default",
        name="Rafaga Anormal de Correo Saliente / Spam Burst",
        description="Incremento masivo de envíos salientes desde una misma cuenta o IP.",
        category="mail",
        severity=85,
        risk_score=90.0,
        event_conditions={
            "service.name": "exim",
            "event.action": "email_sent",
        },
        group_by=["user.name"],
        threshold=200,
        time_window_seconds=300,
    ),
    DetectionRule(
        id="RULE_MAIL_DOVECOT_CREDENTIAL_STUFFING",
        tenant_id="default",
        name="Credential Stuffing IMAP/POP3 (Dovecot)",
        description="Múltiples autenticaciones fallidas de correo IMAP/POP3 desde una IP.",
        category="mail",
        severity=70,
        risk_score=75.0,
        event_conditions={
            "service.name": "dovecot",
            "event.action": "login_failed",
        },
        group_by=["source.ip"],
        threshold=30,
        time_window_seconds=180,
    ),

    # ── Aplicaciones Web ─────────────────────────────────────────────────────
    DetectionRule(
        id="RULE_WEB_WP_LOGIN_BRUTEFORCE",
        tenant_id="default",
        name="Fuerza Bruta WordPress (wp-login.php)",
        description="Detección de solicitudes masivas hacia wp-login.php o xmlrpc.php desde una IP.",
        category="web",
        severity=70,
        risk_score=70.0,
        event_conditions={
            "url.path": "contains:wp-login.php",
        },
        group_by=["source.ip"],
        threshold=40,
        time_window_seconds=300,
    ),
    DetectionRule(
        id="RULE_WEB_WEBSHELL_DETECTED",
        tenant_id="default",
        name="Webshell o PHP Sospechoso Detectado",
        description="Detección activa de webshell en disco por Imunify360 / WAF.",
        category="web",
        severity=95,
        risk_score=98.0,
        event_conditions={
            "event.category": "malware",
        },
        group_by=["host.name", "tenant.id"],
        threshold=1,
        time_window_seconds=60,
    ),
    DetectionRule(
        id="RULE_WEB_MODSEC_EXPLOIT_TRIGGER",
        tenant_id="default",
        name="Ataque WAF ModSecurity Repetitivo",
        description="Múltiples reglas de seguridad ModSecurity activadas por la misma IP.",
        category="web",
        severity=80,
        risk_score=85.0,
        event_conditions={
            "service.name": "modsecurity",
        },
        group_by=["source.ip"],
        threshold=10,
        time_window_seconds=300,
    ),
    DetectionRule(
        id="RULE_WEB_PATH_TRAVERSAL",
        tenant_id="default",
        name="Intento de Path Traversal / LFI",
        description="Solicitud HTTP con patrones de cruce de directorios ('../').",
        category="web",
        severity=85,
        risk_score=88.0,
        event_conditions={
            "url.path": "contains:../",
        },
        group_by=["source.ip"],
        threshold=3,
        time_window_seconds=120,
    ),

    # ── Sistema y SSH ────────────────────────────────────────────────────────
    DetectionRule(
        id="RULE_SYS_SSH_BRUTEFORCE",
        tenant_id="default",
        name="Fuerza Bruta SSH / Acceso no Autorizado",
        description="Múltiples inicios de sesión fallidos por SSH desde una IP.",
        category="system",
        severity=85,
        risk_score=85.0,
        event_conditions={
            "service.name": "sshd",
            "event.action": "login_failed",
        },
        group_by=["source.ip"],
        threshold=15,
        time_window_seconds=300,
    ),
    DetectionRule(
        id="RULE_SYS_PRIVILEGE_ESCALATION",
        tenant_id="default",
        name="Intento de Elevación de Privilegios",
        description="Fallo reiterado de sudo o elevación de privilegios de usuario.",
        category="system",
        severity=90,
        risk_score=95.0,
        event_conditions={
            "service.name": "auditd",
            "event.action": "privilege_escalation",
        },
        group_by=["user.name"],
        threshold=3,
        time_window_seconds=120,
    ),

    # ── Red y Seguridad Perimetral ───────────────────────────────────────────
    DetectionRule(
        id="RULE_NET_CSF_LFD_BLOCK",
        tenant_id="default",
        name="Bloqueo Perimetral por Firewall CSF / LFD",
        description="IP bloqueada automáticamente en el firewall del servidor por comportamiento malicioso.",
        category="network",
        severity=65,
        risk_score=60.0,
        event_conditions={
            "service.name": "lfd",
            "event.action": "ip_blocked",
        },
        group_by=["source.ip"],
        threshold=1,
        time_window_seconds=60,
    ),
]
