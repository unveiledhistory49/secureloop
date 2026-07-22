import os, json, hmac, hashlib
from datetime import datetime, timezone
import config

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def calculate_entry_hash(index: int, timestamp: str, action: str, details: str, previous_hash: str) -> str:
    message = f"{index}|{timestamp}|{action}|{details}|{previous_hash}".encode('utf-8')
    return hmac.new(config.HMAC_KEY, message, hashlib.sha256).hexdigest()

def append_merkle_audit_entry(action: str, details: str) -> dict:
    os.makedirs(os.path.dirname(config.MERKLE_AUDIT_LOG_PATH), exist_ok=True)
    
    entries = []
    if os.path.exists(config.MERKLE_AUDIT_LOG_PATH):
        try:
            with open(config.MERKLE_AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
                entries = json.load(f)
        except Exception:
            entries = []

    index = len(entries)
    previous_hash = entries[-1]["current_hash"] if index > 0 else GENESIS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    
    current_hash = calculate_entry_hash(index, timestamp, action, details, previous_hash)
    
    entry = {
        "index": index,
        "timestamp": timestamp,
        "action": action,
        "details": details,
        "previous_hash": previous_hash,
        "current_hash": current_hash
    }
    
    entries.append(entry)
    
    with open(config.MERKLE_AUDIT_LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)
        
    return entry

def verify_merkle_chain_integrity() -> tuple[bool, str]:
    if not os.path.exists(config.MERKLE_AUDIT_LOG_PATH):
        return True, "No audit log file present yet."
        
    try:
        with open(config.MERKLE_AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
            entries = json.load(f)
    except Exception as e:
        return False, f"Failed to parse audit log: {str(e)}"
        
    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries):
        if entry["index"] != idx:
            return False, f"Index mismatch at entry {idx}"
            
        if entry["previous_hash"] != expected_prev:
            return False, f"Tamper detected! Previous hash broken at entry {idx}"
            
        recalculated = calculate_entry_hash(
            entry["index"],
            entry["timestamp"],
            entry["action"],
            entry["details"],
            entry["previous_hash"]
        )
        
        if recalculated != entry["current_hash"]:
            return False, f"Tamper detected! Cryptographic hash mismatch at entry {idx}"
            
        expected_prev = entry["current_hash"]
        
    return True, f"Cryptographic audit chain intact ({len(entries)} verified entries)."

if __name__ == "__main__":
    entry = append_merkle_audit_entry("SYSTEM_INIT", "Merkle Audit Trail Initialized")
    print("Genesis Entry Created:", entry)
    valid, msg = verify_merkle_chain_integrity()
    print("Integrity Status:", valid, "-", msg)
