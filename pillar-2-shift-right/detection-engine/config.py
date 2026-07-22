import os

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TELEMETRY_LOG_PATH = os.environ.get(
    "TELEMETRY_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/app-telemetry.json")
)

MERKLE_AUDIT_LOG_PATH = os.environ.get(
    "MERKLE_AUDIT_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/merkle-audit-trail.json")
)

ALERTS_LOG_PATH = os.environ.get(
    "ALERTS_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/active-alerts.json")
)

TARGET_APP_URL = os.environ.get("TARGET_APP_URL", "http://localhost:8080")

HMAC_KEY = b"secureloop-merkle-integrity-secret-key-2026"
