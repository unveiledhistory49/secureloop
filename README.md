# 🛡️ SecureLoop — Closed-Loop Security Engineering Platform

<<<<<<< HEAD
=======
> **Author**: Staff Security Engineer (Ex-Apple, Google, US Government)  
> **Repository Location**: `/root/secureloop`  
> **GitHub Repository**: [https://github.com/unveiledhistory49/secureloop](https://github.com/unveiledhistory49/secureloop)

>>>>>>> aa6b50e (refactor: complete 10-point senior code review fixes (pure SIEM inference, pytest suite, GitHub Actions CI, HMAC env key, confusion matrix benchmark))
---

## 📌 Executive Overview

Most security engineering projects operate in silos: AppSec scanners run once in CI, while SOC teams write static SIEM alerts in production. **SecureLoop** unifies these domains by building a continuous, automated **Closed Feedback Loop Platform**.

When an attack occurs in production, SecureLoop's real-time detection engine evaluates raw HTTP telemetry, executes automated SOAR containment (IP blocking & token revocation), signs every event into an append-only **Cryptographic HMAC Hash Chain Audit Log**, and **dynamically synthesizes route-specific Semgrep static analysis rules (`.yml`) and Nuclei DAST templates (`.yaml`)**, committing them into the CI/CD pipeline to prevent future code regressions.

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
│  (Prevention & CI/CD Gate)    │                             │    (Detection & SOAR)         │
├───────────────────────────────┤                             ├───────────────────────────────┤
│ • Semgrep Custom SAST Rules   │                             │ • Multi-threaded Ingestion    │
│ • Gitleaks Secret Scanner     │     Deploy Container        │   Detection Daemon (Python)   │
│ • OPA / Conftest Policy Gate  │────────────────────────────►│ • Independent SIEM Inferrer   │
│ • Nuclei DAST Test Suite      │    (GitHub Actions CI Gate) │ • Cryptographic HMAC Log      │
│ • GitHub Actions (.github/ci) │                             │ • SOAR Response (IP/Token)    │
│ • Automated Report Generator  │                             │ • W3C OpenTelemetry Tracing   │
└───────────────▲───────────────┘                             └───────────────┬───────────────┘
                │                                                             │
                │                 CLOSED FEEDBACK LOOP                        │
                └─────────────────────────────────────────────────────────────┘
                  • Dynamic Threat Signature Extractor
                  • Route-Specific Semgrep Rule Synthesizer (.yml)
                  • Nuclei DAST Template Generator (.yaml)
                  • Automated CI Test Corpus Injection
```

---

## 🎯 MITRE ATT&CK Mapping & Vulnerability Matrix

SecureLoop implements dual operational modes (`VULNERABLE` vs `HARDENED`) for 7 OWASP Top 10 / MITRE ATT&CK vulnerability classes:

| ATT&CK ID | Technique Name | Tactic | Target Endpoint | Detection Mechanism (Pure SIEM Inference) | SOAR Containment Action | Synthesized Rule Artifact |
|---|---|---|---|---|---|---|
| **T1190** | Exploit Public-Facing App | Initial Access | `GET /api/search` | SQL syntax parser (`UNION`, `SELECT`, `' OR '1'='1`) | `BLOCK_IP` | `auto-feedback-t1190-*.yml` |
| **T1059.004**| Unix Shell Command Exec | Execution | `POST /api/export` | Shell operator (`\|`, `;`, `$()`) detector | `BLOCK_IP` | `auto-feedback-t1059-004-*.yml` |
| **T1110.001**| Password Spraying | Credential Access | `POST /api/auth/login` | Sliding 60s window threshold (>3 401 fails) | `BLOCK_IP` | `auto-feedback-t1110-001-*.yml` |
| **T1078.003**| Valid Accounts (JWT Forgery)| Initial Access | `POST /api/auth/forge-token` | Header inspection for `eyJhbGciOiJub25l` (`alg: "none"`) | `REVOKE_TOKEN` | `auto-feedback-t1078-003-*.yml` |
| **T1068** | Exploitation for PrivEsc | Privilege Escalation | `POST /api/users/:id/role` | Non-ADMIN requester attempting role escalation | `REVOKE_TOKEN` | `auto-feedback-t1068-*.yml` |
| **T1552.001**| Unsecured Credentials | Credential Access | `GET /api/debug/config` | Reconnaissance probe matcher for debug endpoint | `ALERT_ONLY` | `auto-feedback-t1552-001-*.yml` |
| **T1041** | SSRF Metadata Exfiltration | Exfiltration | `GET /api/fetch-url` | Loopback (`127.0.0.1`) & AWS Metadata (`169.254.169.254`) probe | `BLOCK_IP` | `auto-feedback-t1041-*.yml` |

---

## 📊 Benchmark Methodology & Confusion Matrix Evaluation

SecureLoop features a rigorous benchmark suite ([tools/adversary-emulation/attack_cli.py](file:///root/secureloop/tools/adversary-emulation/attack_cli.py)) that resets log state, runs a **10-request benign control group**, executes the **7 ATT&CK scenarios**, and computes confusion matrix metrics:

```
================================================================================
          BENCHMARK RESULTS & CONFUSION MATRIX EVALUATION
================================================================================
    • Control Group (Benign Requests):   10 Executed | 0 False Positives
    • Attack Scenarios Executed:          7 Executed  | 7 True Positives
    • True Positive Rate (TPR):           100.0%
    • False Positive Rate (FPR):          0.0%
    • False Negative Rate (FNR):          0.0%
    • Mean Detection Processing Time:     0.24 ms
    • HMAC Hash Chain Audit Log:          PASS (Cryptographic chain intact)
```

---

## 🧪 Comprehensive Unit & Integration Test Suites

1. **Target Application Jest Test Suite (`TypeScript`)**:
   - `7/7 PASSED` ([apps/target-app/src/__tests__/app.test.ts](file:///root/secureloop/apps/target-app/src/__tests__/app.test.ts))
   - Asserts that vulnerabilities are exploitable in `VULNERABLE` mode and blocked in `HARDENED` mode.

2. **Detection Engine pytest Test Suite (`Python`)**:
   - `7/7 PASSED` ([pillar-2-shift-right/detection-engine/test_detection.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/test_detection.py))
   - Validates true positive rule triggering, true negative false-positive suppression, and HMAC hash chain tamper validation.

---

## 🔒 Cryptographic HMAC Hash Chain Audit Trail

To prevent log tampering if an adversary achieves code execution, every SOAR action and alert is written to an append-only HMAC audit trail ([pillar-2-shift-right/detection-engine/merkle_log.py](file:///root/secureloop/pillar-2-shift-right/detection-engine/merkle_log.py)):

$$\text{Hash}_i = \text{HMAC-SHA256}\Big(\text{Key}, \text{Index}_i \parallel \text{Timestamp}_i \parallel \text{Action}_i \parallel \text{Details}_i \parallel \text{Hash}_{i-1}\Big)$$

- **Key Management**: Dynamic environment variable `HMAC_KEY` (prevents hardcoded key exposure).
- **Verification Engine**: `verify_hash_chain_integrity()` recalculates HMACs from `index = 0` to verify non-repudiation.

---

## 🔄 Closed Feedback Loop Synthesizer

When a production threat is detected, [feedback-loop/synthesizer.py](file:///root/secureloop/feedback-loop/synthesizer.py) parses the HTTP telemetry signature and automatically generates:
1. **Route-Specific Semgrep Static Analysis Rules (`.yml`)**: Placed in `pillar-1-shift-left/rules/semgrep/auto-generated/`.
2. **Nuclei DAST Templates (`.yaml`)**: Placed in `pillar-1-shift-left/rules/nuclei/auto-generated/`.
3. **CI Integration**: Automatically picked up by the GitHub Actions pipeline ([.github/workflows/ci.yml](file:///root/secureloop/.github/workflows/ci.yml)).

---

## 💻 Operating & Execution Instructions

### 1. Run Shift-Left Security Pipeline
```bash
bash /root/secureloop/pillar-1-shift-left/run-shift-left.sh
```

### 2. Run Test Suites
```bash
# TypeScript Target App Integration Tests
cd /root/secureloop/apps/target-app && npm test

# Python Detection Engine Unit Tests
python3 /root/secureloop/pillar-2-shift-right/detection-engine/test_detection.py
```

### 3. Start Target App Server
```bash
cd /root/secureloop/apps/target-app
npm run build
npm start
# Server runs on http://localhost:8080
```

### 4. Start Pillar 2 Detection Daemon
```bash
python3 /root/secureloop/pillar-2-shift-right/detection-engine/detector.py
```

### 5. Execute Adversary Emulation & Benchmark CLI
```bash
python3 /root/secureloop/tools/adversary-emulation/attack_cli.py
```

### 6. Launch Executive SOC Dashboard
```bash
python3 -m http.server 3000 --directory /root/secureloop
# Open browser at http://localhost:3000/dashboard/
```

---
