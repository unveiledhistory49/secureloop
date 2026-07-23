import re
from datetime import datetime, timedelta

# Brute force login failure state tracking (IP -> list of timestamps)
login_failures: dict[str, list[datetime]] = {}

def evaluate_log_entry(entry: dict) -> list[dict]:
    """
    Pure SIEM/Detection Rule Engine.
    Infers attacks 100% independently from raw telemetry logs (URL, Method, Headers, Body, UserContext).
    Zero dependency on self-reported application security event labels.
    """
    alerts = []
    
    url = entry.get("url", "")
    method = entry.get("method", "")
    status_code = entry.get("statusCode", 200)
    client_ip = entry.get("clientIp", "127.0.0.1")
    body = entry.get("bodyPayload") or {}
    headers = entry.get("headers") or {}
    user_context = entry.get("userContext") or {}
    timestamp_str = entry.get("timestamp", datetime.now().isoformat())

    body_str = str(body)
    raw_query = url

    # --- RULE 1: T1190 - SQL Injection ---
    sqli_keywords = ["UNION", "SELECT", "' OR '1'='1", "'OR'", "--", "/*", "DROP TABLE", "INFORMATION_SCHEMA"]
    if any(kw.lower() in raw_query.lower() for kw in sqli_keywords) or any(kw.lower() in body_str.lower() for kw in sqli_keywords):
        alerts.append({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application (SQL Injection)",
            "tactic": "Initial Access",
            "severity": "CRITICAL",
            "evidence": f"SQLi payload detected in HTTP request path/body: {url}",
            "attacker_ip": client_ip,
            "recommended_action": "BLOCK_IP"
        })

    # --- RULE 2: T1059.004 - Command Injection ---
    cmd_operators = [";", "&&", "||", "`", "$(", "|"]
    format_val = body.get("format", "") if isinstance(body, dict) else ""
    filename_val = body.get("filename", "") if isinstance(body, dict) else ""
    if any(op in str(format_val) for op in cmd_operators) or any(op in str(filename_val) for op in cmd_operators):
        alerts.append({
            "technique_id": "T1059.004",
            "technique_name": "Command & Scripting Interpreter: Unix Shell",
            "tactic": "Execution",
            "severity": "CRITICAL",
            "evidence": f"OS Command Chaining payload detected in export parameter: {format_val}",
            "attacker_ip": client_ip,
            "recommended_action": "BLOCK_IP"
        })

    # --- RULE 3: T1110.001 - Brute Force (Password Spraying) ---
    if "/api/auth/login" in url and status_code == 401:
        now = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        if client_ip not in login_failures:
            login_failures[client_ip] = []
        login_failures[client_ip].append(now)
        
        # Sliding 60-second window
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

    # --- RULE 4: T1078.003 - Valid Accounts / JWT Alg None Forgery ---
    # Detects JWT header containing base64 for {"alg":"none"...} ("eyJhbGciOiJub25l")
    auth_header = str(headers.get("authorization", "") or headers.get("Authorization", ""))
    if "eyJhbGciOiJub25l" in auth_header:
        alerts.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Unsigned JWT Token Forgery",
            "tactic": "Initial Access",
            "severity": "CRITICAL",
            "evidence": "Authorization bearer header contains forged JWT with alg=none signature bypass",
            "attacker_ip": client_ip,
            "recommended_action": "REVOKE_TOKEN"
        })

    # --- RULE 5: T1068 - Exploitation for Privilege Escalation (IDOR) ---
    # Independent SIEM inference: Non-ADMIN requester attempting to mutate role to ADMIN
    if "/role" in url and (method == "PUT" or method == "POST"):
        requester_role = user_context.get("role", "USER")
        requested_role = body.get("newRole", "") if isinstance(body, dict) else ""
        if requester_role != "ADMIN" and requested_role == "ADMIN":
            alerts.append({
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation (IDOR)",
                "tactic": "Privilege Escalation",
                "severity": "HIGH",
                "evidence": f"Unauthorized user '{user_context.get('username', 'anonymous')}' ({requester_role}) attempted role escalation to ADMIN on {url}",
                "attacker_ip": client_ip,
                "recommended_action": "REVOKE_TOKEN"
            })

    # --- RULE 6: T1552.001 - Unsecured Credentials ---
    # Independent SIEM inference: Request targeting debug config endpoint
    if "/api/debug/config" in url:
        alerts.append({
            "technique_id": "T1552.001",
            "technique_name": "Unsecured Credentials: Secret Leakage Probe",
            "tactic": "Credential Access",
            "severity": "HIGH",
            "evidence": "Reconnaissance request targeting debug secrets endpoint /api/debug/config",
            "attacker_ip": client_ip,
            "recommended_action": "ALERT_ONLY"
        })

    # --- RULE 7: T1041 / SSRF - Exfiltration Over C2 ---
    # Independent SIEM inference: Query param 'url' pointing to internal subnets or cloud metadata
    if "/api/fetch-url" in url:
        ssrf_targets = ["169.254.169.254", "127.0.0.1", "localhost", "10.", "192.168."]
        if any(target in url for target in ssrf_targets):
            alerts.append({
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 / SSRF Metadata Access",
                "tactic": "Exfiltration",
                "severity": "CRITICAL",
                "evidence": f"Outbound SSRF request targeting sensitive internal endpoint in query string: {url}",
                "attacker_ip": client_ip,
                "recommended_action": "BLOCK_IP"
            })

    return alerts
