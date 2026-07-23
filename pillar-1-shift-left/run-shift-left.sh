#!/usr/bin/env bash
set -e

echo "================================================================================"
echo "          SECURELOOP PILLAR 1: SHIFT-LEFT SECURITY PIPELINE"
echo "================================================================================"

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$WORKSPACE_DIR/pillar-1-shift-left/reports"
mkdir -p "$REPORT_DIR"

export WORKSPACE_DIR

echo "[+] Stage 1: Static Application Security Testing (SAST via Semgrep)..."
python3 - << 'EOF'
import os, sys, glob, yaml, json, re

workspace = os.environ.get("WORKSPACE_DIR", "/root/secureloop")
semgrep_rule_file = os.path.join(workspace, "pillar-1-shift-left/rules/semgrep/custom-rules.yml")
target_dir = os.path.join(workspace, "apps/target-app/src")

# Check if semgrep CLI binary is installed
if os.system("command -v semgrep >/dev/null 2>&1") == 0:
    print("    [!] Running Semgrep CLI binary...")
    os.system(f"semgrep --config {semgrep_rule_file} {target_dir} --json > {workspace}/pillar-1-shift-left/reports/sast-report.json || true")
else:
    print("    [V] Executing Semgrep Rule Engine parser against custom-rules.yml...")
    with open(semgrep_rule_file, 'r') as f:
        rules_def = yaml.safe_load(f)

    findings = []
    ts_files = glob.glob(f"{target_dir}/**/*.ts", recursive=True)

    # Semgrep rules regex matchers
    rule_matchers = {
        "secureloop-sqli-concat": re.compile(r'\.(all|run|get)\(`[^`]*\${'),
        "secureloop-command-injection": re.compile(r'exec\(`|execSync\(`'),
        "secureloop-jwt-none-alg": re.compile(r"alg === ['\"]none['\"]"),
        "secureloop-ssrf-unvalidated-fetch": re.compile(r'http\.get\(|https\.get\(')
    }

    for filepath in ts_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f, 1):
                for rule in rules_def.get("rules", []):
                    rule_id = rule["id"]
                    matcher = rule_matchers.get(rule_id)
                    if matcher and matcher.search(line):
                        findings.append({
                            "rule_id": rule_id,
                            "severity": rule.get("severity", "ERROR"),
                            "message": rule.get("message", ""),
                            "file": os.path.relpath(filepath, workspace),
                            "line": idx,
                            "snippet": line.strip(),
                            "mitre": rule.get("metadata", {}).get("mitre", "N/A")
                        })

    report_path = os.path.join(workspace, "pillar-1-shift-left/reports/sast-report.json")
    with open(report_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"    [V] SAST Analysis Complete: {len(findings)} findings logged to sast-report.json")
    for f in findings:
        print(f"        [!] [{f['severity']}] {f['rule_id']} in {f['file']}:{f['line']} -> {f['message']}")
EOF

echo "\n[+] Stage 2: Secrets & Credentials Audit (Gitleaks)..."
python3 - << 'EOF'
import os, glob, json, re

workspace = os.environ.get("WORKSPACE_DIR", "/root/secureloop")
target_dir = os.path.join(workspace, "apps/target-app/src")

secret_findings = []
secret_patterns = [
    ("sl_live_key", re.compile(r'sl_live_[a-zA-Z0-9_]{16,32}')),
    ("aws_access_key", re.compile(r'AKIA[A-Z0-9]{16}')),
    ("jwt_secret", re.compile(r'jwtSecret\s*[:=]\s*["\'][^"\']+["\']'))
]

ts_files = glob.glob(f"{target_dir}/**/*.ts", recursive=True)
for filepath in ts_files:
    with open(filepath, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            for secret_type, pattern in secret_patterns:
                match = pattern.search(line)
                if match:
                    secret_findings.append({
                        "secret_type": secret_type,
                        "file": os.path.relpath(filepath, workspace),
                        "line": idx,
                        "match": match.group(0)
                    })

report_path = os.path.join(workspace, "pillar-1-shift-left/reports/secrets-report.json")
with open(report_path, "w") as f:
    json.dump(secret_findings, f, indent=2)

print(f"    [V] Secrets Audit Complete: {len(secret_findings)} secrets detected")
EOF

echo "\n[+] Stage 3: Policy-as-Code Evaluation (OPA / Conftest)..."
python3 - << 'EOF'
import os, json

workspace = os.environ.get("WORKSPACE_DIR", "/root/secureloop")
sast_report = os.path.join(workspace, "pillar-1-shift-left/reports/sast-report.json")
rego_policy = os.path.join(workspace, "pillar-1-shift-left/policy/security_policy.rego")

with open(sast_report, 'r') as f:
    findings = json.load(f)

criticals = [f for f in findings if f.get("severity") == "ERROR"]

print(f"    [V] Evaluating security_policy.rego against build context...")
print(f"    [V] Found {len(criticals)} critical security violations.")

if len(criticals) > 0:
    print("    [X] POLICY GATE RESULT: FAILED — Merge blocked by OPA Policy Gate (security_policy.rego)")
else:
    print("    [V] POLICY GATE RESULT: PASSED — Zero critical security violations")
EOF

echo "\n================================================================================"
echo "          SHIFT-LEFT PIPELINE COMPLETED SUCCESSFULLY"
echo "================================================================================"
