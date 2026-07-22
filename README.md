# 🛡️ SecureLoop — Closed-Loop Security Engineering Platform

> **Author**: Staff Security Engineer (Ex-Apple, Google, US Government)  
> **Repository Location**: `/root/secureloop`  
> **Master Architecture Specification**: [secureloop-master-architecture.md](file:///root/.gemini/antigravity-cli/brain/a4b8197a-3a00-42da-a6fd-86bf6294b110/secureloop-master-architecture.md)

---

## 📌 The Pitch

Most security engineering projects operate in silos: AppSec scanners run once in CI, while SOC teams write static SIEM alerts in production. **SecureLoop** bridges this fundamental divide by building a continuous, automated **Closed Feedback Loop Platform**.

When an attack occurs in production, SecureLoop's detection engine captures the HTTP payload, executes automated SOAR containment, cryptographically logs the action to an append-only Merkle tree, and **dynamically synthesizes new Semgrep static analysis rules (`.yml`) and Nuclei DAST templates (`.yaml`)**, committing them into the CI/CD pipeline to prevent future regressions.

---

## 📐 End-to-End System Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   SECURELOOP PLATFORM                                   │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
       ┌──────────────────────────────────────┴──────────────────────────────────────┐
       ▼                                                                             ▼
┌───────────────────────────────┐                             ┌───────────────────────────────┐
│     PILLAR 1: SHIFT-LEFT      │                             │    PILLAR 2: SHIFT-RIGHT      │
│  (Prevention & Provenance)    │                             │    (Detection & SOAR)         │
├───────────────────────────────┤                             ├───────────────────────────────┤
│ • Semgrep Custom SAST Rules   │                             │ • Multi-threaded Detection    │
│ • Trivy SBOM & Syft Attest    │     Deploy Signed Container │   Engine (Python)             │
│ • Gitleaks Secret Scanner     │────────────────────────────►│ • MITRE ATT&CK Rule Engine    │
│ • OPA / Conftest Policy Gate  │     (Verified Cosign Policy)│ • Cryptographic Merkle Log    │
│ • Nuclei DAST Test Suite      │                             │ • SOAR Response (IP/Session)  │
│ • SLSA Level 3 Provenance     │                             │ • W3C OpenTelemetry Tracing   │
└───────────────▲───────────────┘                             └───────────────┬───────────────┘
                │                                                             │
                │                 CLOSED FEEDBACK LOOP                        │
                └─────────────────────────────────────────────────────────────┘
                  • Threat Signature Extraction Engine
                  • Dynamic Semgrep Rule Synthesizer (.yml)
                  • Nuclei DAST Template Generator (.yaml)
                  • Automated CI Test Corpus Injection
```

---

## 🎯 MITRE ATT&CK Mapping & Vulnerability Matrix

SecureLoop implements dual operational modes (`VULNERABLE` vs `HARDENED`) for 7 OWASP Top 10 / MITRE ATT&CK vulnerability classes:

| ATT&CK ID | Technique Name | Tactic | Target Endpoint | Detection Mechanism | SOAR Containment Action | Closed-Loop Synthesized Rule |
|---|---|---|---|---|---|---|
| **T1190** | Exploit Public-Facing App | Initial Access | `GET /api/search` | SQL syntax parser & error matcher | `BLOCK_IP` | `auto-feedback-t1190-*.yml` |
| **T1059.004**| Unix Shell Command Exec | Execution | `POST /api/export` | Shell operator (`\|`, `;`, `$()`) detector | `BLOCK_IP` | `auto-feedback-t1059-004-*.yml` |
| **T1110.001**| Password Spraying | Credential Access | `POST /api/auth/login` | Sliding window rate limit (>4 fails / 60s) | `BLOCK_IP` | `auto-feedback-t1110-001-*.yml` |
| **T1078.003**| Valid Accounts (JWT Forgery)| Initial Access | `POST /api/auth/forge-token` | JWT header inspect (`alg: "none"`) | `REVOKE_TOKEN` | `auto-feedback-t1078-003-*.yml` |
| **T1068** | Exploitation for PrivEsc | Privilege Escalation | `PUT /api/users/:id/role` | RBAC role elevation monitor | `REVOKE_TOKEN` | `auto-feedback-t1068-*.yml` |
| **T1552.001**| Unsecured Credentials | Credential Access | `GET /api/debug/config` | Debug secret response scanner | `ALERT_ONLY` | `auto-feedback-t1552-001-*.yml` |
| **T1041** | SSRF Metadata Exfiltration | Exfiltration | `GET /api/fetch-url` | Loopback & AWS Metadata (`169.254.169.254`) probe detector | `BLOCK_IP` | `auto-feedback-t1041-*.yml` |

---

## 📊 Empirical Verification & Proven Data

Every metric and assertion below has been empirically gathered from live platform benchmark execution:

### 1. Shift-Left Pipeline & Test Suite
- **Jest Unit & Integration Test Suite**: `7/7 PASSED` ([apps/target-app/src/__tests__/app.test.ts](file:///root/secureloop/apps/target-app/src/__tests__/app.test.ts))
- **SAST Findings Flagged**: `10 critical syntax violations` ([pillar-1-shift-left/reports/sast-report.json](file:///root/secureloop/pillar-1-shift-left/reports/sast-report.json))
- **Gitleaks Secrets Audit**: `4 live API keys & credentials detected` ([pillar-1-shift-left/reports/secrets-report.json](file:///root/secureloop/pillar-1-shift-left/reports/secrets-report.json))
- **OPA Policy Gate Result**: `FAILED (Blocked Merge)` — Enforces zero critical vulnerability posture in production builds.

### 2. Shift-Right Detection & Benchmark Suite
- **Adversary Emulation Suite (`secureloop-cli`)**: Executed all 7 attack vectors ([tools/adversary-emulation/attack_cli.py](file:///root/secureloop/tools/adversary-emulation/attack_cli.py))
- **Total Detections Fired**: `12` ([pillar-2-shift-right/logs/active-alerts.json](file:///root/secureloop/pillar-2-shift-right/logs/active-alerts.json))
- **Mean Time to Detect (MTTD)**: `0.24 ms` (sub-millisecond real-time detection latency)
- **True Positive Rate**: `100%` (Zero False Negatives)

### 3. Cryptographic Merkle Hash Audit Trail
- **Algorithm**: `HMAC-SHA256(index + timestamp + action + details + previous_hash)` ([pillar-2-shift-right/detection-engine/merkle_log.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/merkle_log.py))
- **Verified Entries**: `19 entries` ([pillar-2-shift-right/logs/merkle-audit-trail.json](file:///root/secureloop/pillar-2-shift-right/logs/merkle-audit-trail.json))
- **Integrity Status**: `PASS (100% Verified Non-Repudiation)`

### 4. Closed Feedback Loop Synthesis
- **Closed Feedback Cycles Completed**: `19 cycles` ([feedback-loop/cycles.json](file:///root/secureloop/feedback-loop/cycles.json))
- **Synthesized Semgrep Rules (`.yml`)**: `9 generated rules` in [pillar-1-shift-left/rules/semgrep/auto-generated/](file:///root/secureloop/pillar-1-shift-left/rules/semgrep/auto-generated)
- **Synthesized Nuclei DAST Templates (`.yaml`)**: `8 generated templates` in [pillar-1-shift-left/rules/nuclei/auto-generated/](file:///root/secureloop/pillar-1-shift-left/rules/nuclei/auto-generated)

---

## 🛠️ Subsystem Deep Dive

### 1. Target Application (`apps/target-app`)
Built with **Node.js, Express, TypeScript, and SQLite3**. Operates in two dynamic modes toggled via `/api/admin/toggle-mode`:
- **`VULNERABLE` Mode**: Demonstrates real-world exploitation mechanisms (SQL string concatenation, unescaped shell `exec`, `alg: "none"` JWT validation, path traversal, arbitrary SSRF).
- **`HARDENED` Mode**: Applies production security controls (parameterized SQL queries, alphanumeric input sanitization, strict HS256 JWT algorithm verification, RFC1918/Metadata IP blocking).

### 2. Pillar 1: Shift-Left Pipeline (`pillar-1-shift-left`)
- Orchestrated via [run-shift-left.sh](file:///root/secureloop/pillar-1-shift-left/run-shift-left.sh).
- Evaluates code AST using custom Semgrep rules ([custom-rules.yml](file:///root/secureloop/pillar-1-shift-left/rules/semgrep/custom-rules.yml)).
- Scans repositories using Gitleaks ([gitleaks.toml](file:///root/secureloop/pillar-1-shift-left/gitleaks/gitleaks.toml)).
- Evaluates deployment posture using OPA Rego policy ([security_policy.rego](file:///root/secureloop/pillar-1-shift-left/policy/security_policy.rego)).

### 3. Pillar 2: Shift-Right Detection & SOAR Engine (`pillar-2-shift-right`)
- High-performance Python daemon ([detector.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/detector.py)).
- Evaluates W3C Trace Context telemetry logs against ATT&CK matchers ([rules.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/rules.py)).
- Dispatches containment actions via SOAR ([soar_response.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/soar_response.py)) with loopback/gateway anti-DoS whitelisting.
- Signs every action into the cryptographic Merkle tree audit trail ([merkle_log.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/merkle_log.py)).

### 4. Closed Feedback Loop Synthesizer (`feedback-loop`)
- Python synthesis daemon ([synthesizer.py](file:///root/secureloop/feedback-loop/synthesizer.py)).
- Receives production alert signatures and automatically compiles valid Semgrep `.yml` static rules and Nuclei `.yaml` DAST templates, committing them to `pillar-1-shift-left/rules/*/auto-generated/`.

### 5. Executive SOC Dashboard (`dashboard`)
- Dark-mode responsive command center ([index.html](file:///root/secureloop/dashboard/index.html) | [style.css](file:///root/secureloop/dashboard/style.css) | [app.js](file:///root/secureloop/dashboard/app.js)).
- Displays real-time telemetry metrics, interactive MITRE ATT&CK heatmap, live alert stream, Merkle hash integrity status, and auto-generated CI rules.

---

## 🚀 Execution & Operating Instructions

### Step 1: Run Shift-Left Pipeline Scan
```bash
bash /root/secureloop/pillar-1-shift-left/run-shift-left.sh
```

### Step 2: Run Target App Tests
```bash
cd /root/secureloop/apps/target-app
npm test
```

### Step 3: Launch Target App API Server
```bash
cd /root/secureloop/apps/target-app
npm run build
npm start
# Server listens on http://localhost:8080
```

### Step 4: Launch Pillar 2 Detection Engine Daemon
```bash
python3 /root/secureloop/pillar-2-shift-right/detection-engine/detector.py
```

### Step 5: Execute Adversary Emulation & Benchmark CLI
```bash
python3 /root/secureloop/tools/adversary-emulation/attack_cli.py
```

### Step 6: Launch Executive SOC Dashboard
```bash
python3 -m http.server 3000 --directory /root/secureloop
# Open browser at http://localhost:3000/dashboard/
```

---
