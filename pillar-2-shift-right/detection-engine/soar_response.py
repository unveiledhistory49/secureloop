import urllib.request, json
import config
from merkle_log import append_merkle_audit_entry

# Safe IPs that cannot be blocked (Anti-DoS protection)
WHITELISTED_IPS = {"127.0.0.1", "localhost", "::1"}

def trigger_ip_block(ip_address: str, reason: str) -> bool:
    if ip_address in WHITELISTED_IPS:
        print(f"[SOAR GUARD] Refusing to block whitelisted loopback IP: {ip_address}")
        return False
        
    url = f"{config.TARGET_APP_URL}/api/soar/block-ip"
    payload = json.dumps({"ip": ip_address}).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                details = f"SOAR AUTOMATED ACTION: Blocked IP {ip_address}. Reason: {reason}"
                append_merkle_audit_entry("SOAR_BLOCK_IP", details)
                print(f"[SOAR RESPONSE] [V] {details}")
                return True
    except Exception as e:
        print(f"[SOAR ERROR] Failed to send IP block request: {e}")
        
    return False

def trigger_token_revocation(token: str, reason: str) -> bool:
    url = f"{config.TARGET_APP_URL}/api/soar/revoke-token"
    payload = json.dumps({"token": token}).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                details = f"SOAR AUTOMATED ACTION: Revoked Token ({token[:15]}...). Reason: {reason}"
                append_merkle_audit_entry("SOAR_REVOKE_TOKEN", details)
                print(f"[SOAR RESPONSE] [V] {details}")
                return True
    except Exception as e:
        print(f"[SOAR ERROR] Failed to send token revocation request: {e}")
        
    return False
