import os

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TELEMETRY_LOG_PATH = os.environ.get(
    "TELEMETRY_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/app-telemetry.json")
)

HASH_CHAIN_AUDIT_LOG_PATH = os.environ.get(
    "HASH_CHAIN_AUDIT_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/merkle-audit-trail.json")
)

ALERTS_LOG_PATH = os.environ.get(
    "ALERTS_LOG_PATH",
    os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/logs/active-alerts.json")
)

TARGET_APP_URL = os.environ.get("TARGET_APP_URL", "http://localhost:8080")

# HMAC Secret Key pulled dynamically from environment variable
HMAC_KEY = os.environ.get("HMAC_KEY", "secureloop-hmac-integrity-secret-key-2026").encode('utf-8')
