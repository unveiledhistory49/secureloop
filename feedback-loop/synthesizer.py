import sys, os, json
from datetime import datetime, timezone
import yaml

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMGREP_AUTO_DIR = os.path.join(WORKSPACE_DIR, "pillar-1-shift-left/rules/semgrep/auto-generated")
NUCLEI_AUTO_DIR = os.path.join(WORKSPACE_DIR, "pillar-1-shift-left/rules/nuclei/auto-generated")
FEEDBACK_CYCLES_PATH = os.path.join(WORKSPACE_DIR, "feedback-loop/cycles.json")

os.makedirs(SEMGREP_AUTO_DIR, exist_ok=True)
os.makedirs(NUCLEI_AUTO_DIR, exist_ok=True)

sys.path.append(os.path.join(WORKSPACE_DIR, "pillar-2-shift-right/detection-engine"))
try:
    from merkle_log import append_audit_entry
except ImportError:
    def append_audit_entry(action, details): pass

def synthesize_semgrep_rule(technique_id: str, evidence: str, raw_url: str) -> str:
    rule_id = f"auto-feedback-{technique_id.lower().replace('.', '-')}-{int(datetime.now().timestamp())}"
    
    # Specific AST pattern mapping per technique ID
    pattern_mapping = {
        "T1190": [{"pattern": "$DB.all(`... ${$QUERY} ...`, ...)"}, {"pattern": "$DB.run(`... ${$QUERY} ...`, ...)"}],
        "T1059.004": [{"pattern": "exec(`... ${$CMD} ...`, ...)"}, {"pattern": "execSync(`... ${$CMD} ...`, ...)"}],
        "T1078.003": [{"pattern": "if ($HEADER.alg === 'none') { ... }"}],
        "T1068": [{"pattern": "$APP.put('/:id/role', ...)"}, {"pattern": "$APP.post('/:id/role', ...)"}],
        "T1552.001": [{"pattern": "res.json({ ..., jwtSecret: $S, ... })"}],
        "T1041": [{"pattern": "http.get($URL, ...)"}, {"pattern": "https.get($URL, ...)"}]
    }

    patterns = pattern_mapping.get(technique_id, [{"pattern": "$REQ.query"}, {"pattern": "$REQ.body"}])

    rule_data = {
        "rules": [
            {
                "id": rule_id,
                "message": f"AUTO-FEEDBACK-RULE: AST rule synthesized from prod attack detection {technique_id}: {evidence}",
                "severity": "ERROR",
                "languages": ["typescript", "javascript"],
                "patterns": [{"pattern-either": patterns}],
                "metadata": {
                    "generated_by": "SecureLoop Closed Feedback Synthesizer",
                    "mitre": technique_id,
                    "target_url": raw_url
                }
            }
        ]
    }
    
    rule_path = os.path.join(SEMGREP_AUTO_DIR, f"{rule_id}.yml")
    with open(rule_path, 'w', encoding='utf-8') as f:
        yaml.dump(rule_data, f, default_flow_style=False)
        
    return rule_path

def synthesize_nuclei_template(technique_id: str, raw_url: str, body: dict) -> str:
    template_id = f"dast-auto-{technique_id.lower().replace('.', '-')}-{int(datetime.now().timestamp())}"
    
    clean_url = raw_url.split('?')[0] if '?' in raw_url else raw_url
    query_str = raw_url.split('?')[1] if '?' in raw_url else ""
    
    template_data = f"""id: {template_id}
info:
  name: Auto-Generated Nuclei DAST Template for {technique_id}
  author: SecureLoop Closed Feedback Synthesizer
  severity: high
  tags: dast,closed-loop,{technique_id.lower()}

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{clean_url}?{query_str}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
"""
    
    template_path = os.path.join(NUCLEI_AUTO_DIR, f"{template_id}.yaml")
    with open(template_path, 'w', encoding='utf-8') as f:
        f.write(template_data)
        
    return template_path

def process_feedback_cycle(alert: dict, raw_log: dict):
    technique_id = alert.get("technique_id", "UNKNOWN")
    evidence = alert.get("evidence", "")
    raw_url = raw_log.get("url", "")
    body = raw_log.get("bodyPayload") or {}
    
    semgrep_file = synthesize_semgrep_rule(technique_id, evidence, raw_url)
    nuclei_file = synthesize_nuclei_template(technique_id, raw_url, body)
    
    cycle_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trigger_alert": technique_id,
        "evidence": evidence,
        "generated_semgrep_rule": os.path.basename(semgrep_file),
        "generated_nuclei_template": os.path.basename(nuclei_file),
        "status": "CI_GATE_UPDATED"
    }
    
    cycles = []
    if os.path.exists(FEEDBACK_CYCLES_PATH):
        try:
            with open(FEEDBACK_CYCLES_PATH, 'r', encoding='utf-8') as f:
                cycles = json.load(f)
        except Exception:
            cycles = []
    cycles.append(cycle_record)
    with open(FEEDBACK_CYCLES_PATH, 'w', encoding='utf-8') as f:
        json.dump(cycles, f, indent=2)
        
    append_audit_entry(
        "FEEDBACK_LOOP_CYCLE_COMPLETE",
        f"Synthesized Semgrep ({os.path.basename(semgrep_file)}) & Nuclei DAST template for {technique_id}"
    )
    
    print(f"[FEEDBACK SYNTHESIZER] [V] Successfully closed loop for {technique_id} -> Generated CI static rule & DAST test case.")

if __name__ == "__main__":
    if not sys.stdin.isatty():
        try:
            input_data = sys.stdin.read()
            payload = json.loads(input_data)
            alert = payload.get("alert", {})
            raw_log = payload.get("raw_log", {})
            process_feedback_cycle(alert, raw_log)
        except Exception as e:
            print(f"Error reading stdin: {e}")
    else:
        sample_alert = {
            "technique_id": "T1190",
            "evidence": "SQL Injection payload ' OR '1'='1 in /api/search"
        }
        sample_log = {
            "url": "/api/search?q=' OR '1'='1",
            "bodyPayload": {}
        }
        process_feedback_cycle(sample_alert, sample_log)
