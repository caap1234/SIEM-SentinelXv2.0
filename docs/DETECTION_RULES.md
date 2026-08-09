# Catálogo de Reglas de Detección de Hosting - SentinelX SIEM

## Reglas Predeterminadas de Detección

### 1. Correo Electrónico (Mail)
- **`RULE_MAIL_SMTP_AUTH_BRUTEFORCE`**: >50 fallos SMTP AUTH desde una IP en 5 min. (Severidad: 75)
- **`RULE_MAIL_HIGH_OUTBOUND_SPAM`**: >200 envíos salientes desde un usuario/cuenta en 5 min. (Severidad: 85)
- **`RULE_MAIL_DOVECOT_CREDENTIAL_STUFFING`**: >30 autenticaciones fallidas IMAP/POP3 en 3 min. (Severidad: 70)

### 2. Aplicaciones Web (Web)
- **`RULE_WEB_WP_LOGIN_BRUTEFORCE`**: >40 peticiones a `wp-login.php` desde una IP en 5 min. (Severidad: 70)
- **`RULE_WEB_WEBSHELL_DETECTED`**: Detección de webshell por Imunify360 en 1 min. (Severidad: 95)
- **`RULE_WEB_MODSEC_EXPLOIT_TRIGGER`**: >10 activaciones WAF ModSecurity desde una IP en 5 min. (Severidad: 80)
- **`RULE_WEB_PATH_TRAVERSAL`**: >3 patrones de cruce de directorios en 2 min. (Severidad: 85)

### 3. Sistema y SSH (System)
- **`RULE_SYS_SSH_BRUTEFORCE`**: >15 inicios de sesión fallidos SSH desde una IP en 5 min. (Severidad: 85)
- **`RULE_SYS_PRIVILEGE_ESCALATION`**: >3 fallos de elevación de privilegios `sudo` en 2 min. (Severidad: 90)

### 4. Red y Firewall (Network)
- **`RULE_NET_CSF_LFD_BLOCK`**: Bloqueo automático de IP registrado por CSF / LFD. (Severidad: 65)
