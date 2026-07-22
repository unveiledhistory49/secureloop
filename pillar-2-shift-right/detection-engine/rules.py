import re
from datetime import datetime, timedelta

# Brute force login failure state tracking (IP -> list of timestamps)
login_failures: dict[str, list[datetime]] = {}

def evaluate_log_entry(entry: dict) -> list[dict]:
    alerts = []
    
    url = entry.get("url", "")
    method = entry.get("method", "")
    client_ip = entry.get("clientIp", "127.0.0.1")
    body = entry.get("bodyPayload") or {}
    sec_event = entry.get("securityEvent")
    timestamp_str = entry.get("timestamp", datetime.now().isoformat())

    # --- RULE 1: T1190 - SQL Injection ---
    sqli_keywords = ["UNION", "SELECT", "' OR '1'='1", "'OR'", "--", "/*", "DROP TABLE", "INFORMATION_SCHEMA"]
    body_str = str(body)
    raw_query = url
    
    if any(kw.lower() in raw_query.lower() for kw in sqli_keywords) or any(kw.lower() in body_str.lower() for kw in sqli_keywords) or (sec_event and sec_event.get("type") == "SQL_ERROR_EXPLOIT"):
        alerts.append({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application (SQL Injection)",
            "tactic": "Initial Access",
            "severity": "CRITICAL",
            "evidence": f"SQLi payload detected in URL/Body: {url}",
            "attacker_ip": client_ip,
            "recommended_action": "BLOCK_IP"
        })

    # --- RULE 2: T1059.004 - Command Injection ---
    cmd_operators = [";", "&&", "||", "`", "$(", "|"]
    format_val = body.get("format", "") if isinstance(body, dict) else ""
    filename_val = body.get("filename", "") if isinstance(body, dict) else ""
    
    if any(op in str(format_val) for op in cmd_operators) or any(op in str(filename_val) for op in cmd_operators) or (sec_event and sec_event.get("type") == "COMMAND_EXECUTION_ERROR"):
        alerts.append({
            "technique_id": "T1059.004",
            "technique_name": "Command & Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "severity": "CRITICAL",
            "evidence": f"OS Command Chaining payload detected in export endpoint: {format_val}",
            "attacker_ip": client_ip,
            "recommended_action": "BLOCK_IP"
        })

    # --- RULE 3: T1110.001 - Brute Force (Password Spraying) ---
    if sec_event and sec_event.get("type") == "AUTH_FAILURE":
        now = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        if client_ip not in login_failures:
            login_failures[client_ip] = []
        login_failures[client_ip].append(now)
        
        # Sliding window 60 seconds
        cutoff = now - timedelta(seconds=60)
        login_failures[client_ip] = [t for t in login_failures[client_ip] if t >= cutoff]
        
        if len(login_failures[client_ip]) >= 4:
            alerts.append({
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Spraying",
                "tactic": "Credential Access",
                "severity": "HIGH",
                "evidence": f"High frequency authentication failures: {len(login_failures[client_ip])} attempts in 60s from {client_ip}",
                "attacker_ip": client_ip,
                "recommended_action": "BLOCK_IP"
            })

    # --- RULE 4: T1078.003 - Valid Accounts / JWT Alg None ---
    if sec_event and sec_event.get("type") == "JWT_ALG_NONE_EXPLOIT":
        alerts.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Unsigned JWT Token Forgery",
            "tactic": "Initial Access",
            "severity": "CRITICAL",
            "evidence": sec_event.get("details"),
            "attacker_ip": client_ip,
            "recommended_action": "REVOKE_TOKEN"
        })

    # --- RULE 5: T1068 - Exploitation for Privilege Escalation (IDOR) ---
    if sec_event and sec_event.get("type") == "PRIVILEGE_ESCALATION_DETECTED":
        alerts.append({
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "severity": "HIGH",
            "evidence": sec_event.get("details"),
            "attacker_ip": client_ip,
            "recommended_action": "REVOKE_TOKEN"
        })

    # --- RULE 6: T1552.001 - Unsecured Credentials ---
    if sec_event and sec_event.get("type") == "SECRET_LEAKAGE_EXPLOIT":
        alerts.append({
            "technique_id": "T1552.001",
            "technique_name": "Unsecured Credentials: Secret Leakage in Debug Endpoint",
            "tactic": "Credential Access",
            "severity": "HIGH",
            "evidence": "Access to /api/debug/config exposed secrets",
            "attacker_ip": client_ip,
            "recommended_action": "ALERT_ONLY"
        })

    # --- RULE 7: T1041 / SSRF - Exfiltration Over C2 ---
    if sec_event and sec_event.get("type") == "SSRF_METADATA_ATTEMPT":
        alerts.append({
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 / SSRF Metadata Access",
            "tactic": "Exfiltration",
            "severity": "CRITICAL",
            "evidence": sec_event.get("details"),
            "attacker_ip": client_ip,
            "recommended_action": "BLOCK_IP"
        })

    return alerts
