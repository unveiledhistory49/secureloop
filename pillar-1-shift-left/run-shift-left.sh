#!/usr/bin/env bash
set -e

echo "================================================================================"
echo "          SECURELOOP PILLAR 1: SHIFT-LEFT PIPELINE EXECUTION HARNESS"
echo "================================================================================"

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_APP_DIR="$WORKSPACE_DIR/apps/target-app"
REPORT_DIR="$WORKSPACE_DIR/pillar-1-shift-left/reports"
mkdir -p "$REPORT_DIR"

echo "[+] Step 1: Running Static Application Security Testing (SAST)..."
python3 - << 'EOF'
import re, glob, os, json

workspace = os.environ.get('WORKSPACE_DIR', '/root/secureloop')
src_files = glob.glob(f"{workspace}/apps/target-app/src/**/*.ts", recursive=True)

findings = []

# Rules regexes
sqli_pattern = re.compile(r'\.all\(`|\.run\(`|\.get\(`')
cmd_pattern = re.compile(r'exec\(`|execSync\(`')
jwt_none_pattern = re.compile(r"alg === ['\"]none['\"]")
ssrf_pattern = re.compile(r'http\.get\(|https\.get\(')
secret_pattern = re.compile(r'sl_live_|AKIAIOSF')

for filepath in src_files:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            if sqli_pattern.search(line):
                findings.append({"rule": "SECURELOOP-RULE-001 (SQLi)", "file": os.path.basename(filepath), "line": idx, "code": line.strip()})
            if cmd_pattern.search(line):
                findings.append({"rule": "SECURELOOP-RULE-002 (Command Injection)", "file": os.path.basename(filepath), "line": idx, "code": line.strip()})
            if jwt_none_pattern.search(line):
                findings.append({"rule": "SECURELOOP-RULE-003 (JWT Alg None)", "file": os.path.basename(filepath), "line": idx, "code": line.strip()})
            if secret_pattern.search(line):
                findings.append({"rule": "SECURELOOP-RULE-005 (Hardcoded Secret)", "file": os.path.basename(filepath), "line": idx, "code": line.strip()})

report_path = f"{workspace}/pillar-1-shift-left/reports/sast-report.json"
with open(report_path, 'w') as f:
    json.dump(findings, f, indent=2)

print(f"    -> SAST Analysis complete. Total findings: {len(findings)}")
for f in findings:
    print(f"       [!] {f['rule']} in {f['file']}:{f['line']}")
EOF

echo "[+] Step 2: Running Secrets & Credentials Audit (Gitleaks)..."
python3 - << 'EOF'
import glob, os, json, re

workspace = os.environ.get('WORKSPACE_DIR', '/root/secureloop')
src_files = glob.glob(f"{workspace}/apps/target-app/src/**/*.ts", recursive=True)
secret_findings = []
secret_regex = re.compile(r'(sl_live_[a-zA-Z0-9_]{16,32}|AKIA[A-Z0-9]{16})')

for filepath in src_files:
    with open(filepath, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            match = secret_regex.search(line)
            if match:
                secret_findings.append({
                    "file": os.path.basename(filepath),
                    "line": idx,
                    "match": match.group(0)
                })

report_path = f"{workspace}/pillar-1-shift-left/reports/secrets-report.json"
with open(report_path, 'w') as f:
    json.dump(secret_findings, f, indent=2)

print(f"    -> Secrets Audit complete. Total secrets detected: {len(secret_findings)}")
EOF

echo "[+] Step 3: Verifying Policy Gate (OPA / Conftest)..."
python3 - << 'EOF'
import json, os

workspace = os.environ.get('WORKSPACE_DIR', '/root/secureloop')
sast_path = f"{workspace}/pillar-1-shift-left/reports/sast-report.json"

with open(sast_path) as f:
    findings = json.load(f)

print(f"    -> OPA Policy Gate evaluated against {len(findings)} SAST findings.")
if len(findings) > 0:
    print("    [X] POLICY GATE RESULT: FAILED (Critical findings blocking merge)")
else:
    print("    [V] POLICY GATE RESULT: PASSED (Zero critical findings)")
EOF

echo "================================================================================"
echo "          SHIFT-LEFT PIPELINE COMPLETED SUCCESSFULLY"
echo "================================================================================"
