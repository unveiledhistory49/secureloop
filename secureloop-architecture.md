# SecureLoop — Full-Lifecycle Security Engineering Platform

*(working title — rename freely)*

## The pitch

Most portfolio security projects prove you can run a scanner once. This one proves you can own the entire security lifecycle: prevent (shift-left), detect (shift-right), and — the part almost nobody builds — feed what you detect in production back into what you prevent in CI. That closed loop is the actual differentiator.

It merges the two original ideas into one project with two pillars sharing a single target app, so the interview narrative is one sentence: *"I built an app, hardened its delivery pipeline, deployed it, then built the detection and response layer that watches it in production — and wired the two together so each one makes the other better."*

## Architecture overview

```
 ┌────────────────────────┐        ┌───────────────────────────┐
 │  PILLAR 1: SHIFT-LEFT   │        │  PILLAR 2: SHIFT-RIGHT     │
 │  (prevent)              │        │  (detect & respond)        │
 │                         │        │                            │
 │  PR → CI pipeline:      │        │  Prod app → logs →         │
 │  SAST / SCA / secrets / │───────▶│  detection engine →        │
 │  IaC scan / DAST →      │ deploy │  ATT&CK-mapped alerts →     │
 │  policy gate → signed   │        │  automated response        │
 │  image                  │        │                            │
 └────────────▲────────────┘        └─────────────┬──────────────┘
              │                                    │
              └────────────── feedback loop ───────┘
              (confirmed prod exploit → new CI test/rule)
```

## Component breakdown

**Target app** — a small, realistic app you build yourself (not a stock vulnerable app like Juice Shop), deliberately seeded with real vuln classes: SQL injection in a search endpoint, IDOR on resource lookups, broken JWT handling, unrestricted file upload, SSRF in an external-lookup feature (e.g. "fetch exchange rate"), hardcoded secrets, no rate limiting. Building your own beats reusing a known-vulnerable app, because it proves you understand *why* each bug is exploitable, not just that a scanner flagged it.

**Pillar 1 — Shift-left pipeline**
- GitHub Actions stages, each a merge-blocking gate: SAST (Semgrep), SCA + SBOM (Trivy + Syft), secrets scan (Gitleaks), IaC scan (Checkov on your Terraform), DAST (OWASP ZAP against an ephemeral staging instance), policy check (OPA/Conftest — e.g. "no criticals," "every endpoint requires auth")
- Signed container image (cosign) as the deploy artifact
- Findings surfaced as PR review comments, not buried in a log

**Pillar 2 — Detection & response**
- Structured logs (app, auth, access) shipped to Loki or OpenSearch
- Detection rules mapped explicitly to a starter set of MITRE ATT&CK techniques (verified IDs below)
- Automated response: block an IP, flag/disable an account, page Slack/PagerDuty with the technique ID and recommended action
- Every automated action written to an append-only, hash-chained log — a tamper-evident audit trail, cheap to build and disproportionately impressive in review

**Suggested starter technique set** (spans four tactics, realistic for a small web app to actually generate signal on):
| ID | Technique | Tactic |
|---|---|---|
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts (anomalous / impossible-travel logins) | Initial Access / Persistence |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1552 | Unsecured Credentials | Credential Access |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |

**The feedback loop** — when a simulated or real attack succeeds against pillar 2, it auto-files a GitHub issue linking the exact payload/pattern to a new DAST test case or Semgrep rule. This is the single most "senior engineer" detail in the whole project: most people build detection *or* prevention. Few build the thing that makes each one improve the other over time.

## Testing strategy

Treat this like a real security testing pyramid, not just "add pytest":

1. **Unit** — each detection rule tested against synthetic log lines: true positive on the attack pattern, true negative on benign traffic. False-positive control matters as much as catching the attack.
2. **Integration** — pipeline gates actually block a PR seeded with a known-vulnerable dependency; the log pipeline correctly parses and forwards each log format end to end.
3. **E2E** — scripted attack (Atomic Red Team–style, mapped to the technique table above) → detection fires within a target latency → correct automated response executes (verify the IP is *actually* blocked by attempting a follow-up connection) → alert lands in Slack.
4. **Red-team regression** — a standing corpus of OWASP Top 10 payloads run periodically against the app; asserts both layers still catch what they used to catch.
5. **Detection-of-absence** — if the log pipeline goes down, that itself should alert. An unknown blind spot is worse than a known bug.
6. **The metrics that are your real test assertions**: false positive rate, false negative rate (scored against your attack corpus as ground truth), mean time to detect (MTTD), mean time to respond (MTTR). Track these over time the way you'd track code coverage.

## Milestone plan (~8–10 weeks, part-time)

| Phase | Focus | Est. time |
|---|---|---|
| 0 | Repo scaffold, IaC skeleton, lock in the ATT&CK technique list | 2–3 days |
| 1 | Build the vulnerable target app + its own functional tests | ~1 week |
| 2 | Wire the shift-left pipeline gate by gate; write the "before" pentest report | 1.5–2 weeks |
| 3 | Remediate every finding; document each fix before/after | 3–5 days |
| 4 | Deploy the hardened app; stand up the logging pipeline + dashboard | ~1 week |
| 5 | Write detection rules; unit test each against synthetic logs | 1.5–2 weeks |
| 6 | Adversary emulation; tune detections; capture MTTD/FP/FN metrics | ~1 week |
| 7 | Build the feedback loop (detection → new CI test/rule) | 3–4 days |
| 8 | README, architecture diagram, demo clip, write-up of 1–2 attack scenarios end to end | 3–5 days |

## Cost note

This doesn't need real cloud spend. Local Docker Compose covers most of pillar 1. Pillar 2 can run on a single cheap VM (or a free-tier instance) with Loki instead of full ELK to keep it light. Flag anywhere a paid service would meaningfully help, but nothing here requires one.

## What this proves to a reviewer

Full SDLC ownership, not "I ran a scanner." Detection engineering mapped to a real framework, not ad hoc rules. Understanding of both offense (you found and exploited the bugs) and defense (you fixed them, then built monitoring for the ones you'll miss next time). The feedback loop shows systems thinking most candidates don't demonstrate.

## Stretch goals

- A coverage dashboard scoring detection maturity per ATT&CK tactic (visually shows gaps)
- Canary tokens seeded in the app to catch attacker recon before real damage happens
- A second, structurally different vulnerable app to prove the pipeline generalizes, not hardcoded to one codebase
