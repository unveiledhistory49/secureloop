import os, sys, json, pytest, config
from datetime import datetime, timezone

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from rules import evaluate_log_entry
from merkle_log import append_audit_entry, verify_hash_chain_integrity

def test_sqli_true_positive():
    log_entry = {
        "url": "/api/search?q=' OR '1'='1",
        "method": "GET",
        "clientIp": "192.168.1.100",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1190"

def test_sqli_true_negative():
    log_entry = {
        "url": "/api/search?q=Software",
        "method": "GET",
        "clientIp": "192.168.1.100",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 0

def test_command_injection_true_positive():
    log_entry = {
        "url": "/api/export",
        "method": "POST",
        "bodyPayload": {"filename": "report", "format": "txt$(id)"},
        "clientIp": "192.168.1.101",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1059.004"

def test_jwt_none_true_positive():
    log_entry = {
        "url": "/api/users/usr-001",
        "method": "GET",
        "headers": {"authorization": "Bearer eyJhbGciOiJub25lIn0.payload.signature"},
        "clientIp": "192.168.1.102",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1078.003"

def test_privilege_escalation_true_positive():
    log_entry = {
        "url": "/api/users/usr-002/role",
        "method": "POST",
        "bodyPayload": {"newRole": "ADMIN"},
        "userContext": {"username": "alice", "role": "USER"},
        "clientIp": "192.168.1.103",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 1
    assert alerts[0]["technique_id"] == "T1068"

def test_privilege_escalation_true_negative_admin():
    log_entry = {
        "url": "/api/users/usr-002/role",
        "method": "POST",
        "bodyPayload": {"newRole": "ADMIN"},
        "userContext": {"username": "admin", "role": "ADMIN"},
        "clientIp": "192.168.1.104",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    alerts = evaluate_log_entry(log_entry)
    assert len(alerts) == 0

def test_hash_chain_integrity():
    # Clear test file for isolated unit test assertion
    if os.path.exists(config.HASH_CHAIN_AUDIT_LOG_PATH):
        with open(config.HASH_CHAIN_AUDIT_LOG_PATH, 'w') as f:
            json.dump([], f)

    entry1 = append_audit_entry("TEST_ACTION_1", "Audit entry 1 details")
    entry2 = append_audit_entry("TEST_ACTION_2", "Audit entry 2 details")
    valid, msg = verify_hash_chain_integrity()
    assert valid is True

if __name__ == "__main__":
    pytest.main([__file__])
