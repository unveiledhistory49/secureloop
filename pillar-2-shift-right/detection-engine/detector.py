import os, time, json
from datetime import datetime, timezone
import config
from rules import evaluate_log_entry
from soar_response import trigger_ip_block, trigger_token_revocation
from merkle_log import append_merkle_audit_entry

# Ensure directories exist
os.makedirs(os.path.dirname(config.ALERTS_LOG_PATH), exist_ok=True)

def append_active_alert(alert: dict):
    alerts = []
    if os.path.exists(config.ALERTS_LOG_PATH):
        try:
            with open(config.ALERTS_LOG_PATH, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
        except Exception:
            alerts = []
    alerts.append(alert)
    with open(config.ALERTS_LOG_PATH, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)

def notify_feedback_loop(alert: dict, raw_log: dict):
    """
    Triggers the closed feedback loop synthesizer to automatically generate
    new Semgrep static rules (.yml) and Nuclei DAST templates (.yaml).
    """
    try:
        feedback_script = os.path.join(config.WORKSPACE_DIR, "feedback-loop/synthesizer.py")
        if os.path.exists(feedback_script):
            import subprocess
            input_json = json.dumps({"alert": alert, "raw_log": raw_log})
            res = subprocess.run(
                ["python3", feedback_script],
                input=input_json,
                text=True,
                capture_output=True,
                timeout=5
            )
            print(f"[FEEDBACK LOOP] Synthesizer output: {res.stdout.strip()}")
    except Exception as e:
        print(f"[FEEDBACK LOOP ERROR] Failed to invoke feedback synthesizer: {e}")

def run_detection_daemon(poll_interval: float = 0.5):
    print("================================================================================")
    print("          SECURELOOP PILLAR 2: DETECTION & RESPONSE DAEMON STARTED")
    print(f"          Log Source: {config.TELEMETRY_LOG_PATH}")
    print("================================================================================")

    last_processed_pos = 0

    while True:
        if not os.path.exists(config.TELEMETRY_LOG_PATH):
            time.sleep(poll_interval)
            continue

        try:
            with open(config.TELEMETRY_LOG_PATH, 'r', encoding='utf-8') as f:
                f.seek(last_processed_pos)
                lines = f.readlines()
                last_processed_pos = f.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                detection_start = time.time()
                alerts = evaluate_log_entry(entry)

                for alert in alerts:
                    mttd_ms = round((time.time() - detection_start) * 1000, 2)
                    alert["mttd_ms"] = mttd_ms
                    alert["detected_at"] = datetime.now(timezone.utc).isoformat()
                    alert["trace_id"] = entry.get("traceId")

                    print(f"\n[ALERT MATCHED] [{alert['severity']}] {alert['technique_id']} - {alert['technique_name']}")
                    print(f"               Evidence: {alert['evidence']}")
                    print(f"               MTTD Latency: {mttd_ms} ms")

                    append_active_alert(alert)
                    append_merkle_audit_entry("ALERT_GENERATED", f"{alert['technique_id']}: {alert['evidence']}")

                    # SOAR Action Dispatch
                    action = alert.get("recommended_action")
                    if action == "BLOCK_IP":
                        trigger_ip_block(alert["attacker_ip"], alert["evidence"])
                    elif action == "REVOKE_TOKEN":
                        auth_header = entry.get("headers", {}).get("authorization", "")
                        token = auth_header.split(" ")[1] if " " in auth_header else "unknown"
                        trigger_token_revocation(token, alert["evidence"])

                    # Closed Feedback Loop Invocation
                    notify_feedback_loop(alert, entry)

        except Exception as e:
            print(f"[DETECTOR ERROR] Daemon exception: {e}")

        time.sleep(poll_interval)

if __name__ == "__main__":
    run_detection_daemon()
