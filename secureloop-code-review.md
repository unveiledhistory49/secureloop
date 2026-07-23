# SecureLoop — Code Review

## Verdict

**As a narrated demo, this is a solid 7/10** — genuinely more functional than most security portfolio projects, with real exploitable vulnerabilities, a real tamper-evident log, and a live dashboard.

**As a repo a senior engineer actually clones and reads, it's closer to a 4/10 right now** — not because the underlying skill isn't there (it clearly is: your Semgrep/Gitleaks/Rego config syntax is all correct, your hash-chain logic is sound), but because the README describes a system that doesn't match what the code does in several load-bearing places. That specific mismatch — claims vs. implementation — is the single most damaging thing you can walk an interviewer into, more damaging than the gaps themselves would be if described honestly.

The fix list below is mostly wiring, not rewriting.

---

## What's genuinely real and good

- **The vulnerabilities are real.** `search.ts` builds SQL via raw template-string interpolation; `export.ts` shells out via `exec()` with unsanitized input; `users.ts` has a genuine missing-authorization-check IDOR; `fetch.ts` does an unguarded outbound fetch. All four are actually exploitable, and the `HARDENED` mode fixes are the *correct* fixes (parameterized queries, input allowlisting, role check, private-IP blocking) — not hand-wavy.
- **The hash-chain audit log works.** `merkle_log.py`'s `verify_merkle_chain_integrity()` genuinely recomputes HMACs and would catch tampering. Solid.
- **The Jest suite makes real assertions**, not smoke tests — e.g. asserting the SQLi payload returns 0 rows specifically in `HARDENED` mode, not just a 200 status.
- **The dashboard is real**, not a mockup — `app.js` polls `active-alerts.json`, `merkle-audit-trail.json`, and `cycles.json` on a 2s interval and reflects actual state.
- **The SOAR block is enforced**, not decorative — `logger.ts` checks `config.blockedIps.has(clientIp)` and actually returns 403 on subsequent requests.
- **You know the real tool syntax** — `gitleaks.toml`, `custom-rules.yml` (Semgrep), and `security_policy.rego` are all correctly formed. This means the gap below is an integration gap, not a knowledge gap.

---

## Critical gaps (claims vs. implementation)

### 1. Pillar 1 never calls Semgrep, Gitleaks, OPA, Nuclei, or Trivy

`pillar-1-shift-left/run-shift-left.sh` has exactly three steps, and all three are hand-rolled Python:

- "SAST" = a regex scan (`\.all\(\``, `exec\(\``, etc.) over `.ts` files — not Semgrep, doesn't touch `custom-rules.yml`
- "Gitleaks" = a hardcoded regex for one fake key prefix — doesn't shell out to `gitleaks detect`, doesn't reference `gitleaks.toml`
- "OPA/Conftest" = `if len(findings) > 0: print FAILED` — never evaluates `security_policy.rego`

There's no DAST step, no Trivy/SBOM step, no container build, no cosign signing anywhere in this script — despite the README claiming all of these. And the root `package.json` has **zero dependencies**, confirming none of these tools are even installed.

**Fix**: since your config files are already correct, this is mostly: `pip install semgrep`, `brew/apt install gitleaks conftest`, then replace each Python block with the real CLI call against the file you already wrote. Hours, not days.

### 2. No CI/CD at all

There is no `.github/workflows/` directory anywhere in the repo. "Shift-left" and "merge-blocking gate" both require the pipeline to run automatically on a PR — right now it's a script a human has to remember to run locally. This is the single easiest high-impact fix: one YAML file that runs `run-shift-left.sh` (once it's real) on `pull_request` and fails the check on findings.

### 3. Four of seven "detections" are the app self-reporting, not detection

In `rules.py`, three rules genuinely infer an attack from raw signal:
- SQLi: keyword matching on URL/body content
- Command injection: shell-operator matching on specific fields
- Brute force: a real stateful sliding-window counter (this one is legitimately well done)

But JWT forgery, privilege escalation, secret leakage, and SSRF all gate on `if sec_event.get("type") == "X"` — and `sec_event` is a label the *vulnerable route itself* attaches. Concretely, in `users.ts`, the instant the (intentionally unprotected) role-update endpoint is hit at all, it writes `securityEvent: { type: 'PRIVILEGE_ESCALATION_DETECTED' }` regardless of whether the change was legitimate. The Python detector for these four isn't analyzing behavior — it's forwarding a ground-truth label the app already computed.

**Fix**: for at least one of these four, implement real inference — e.g., privilege escalation should be detected by the Python layer comparing the requester's role against the action taken (using `userContext` + the request body), not by trusting a label the vulnerable code pre-attached. Even fixing one of the four honestly would materially change how this reads in an interview.

### 4. The benchmark metrics oversell what was measured

`attack_cli.py` runs each of the 7 attacks exactly once, against a target it assumes is already in `VULNERABLE` mode, then reads the alerts file — which is **cumulative across every run you've ever done**, never reset. So "12 detections" / "19 audit entries" are just whatever happened to accumulate during development, not a controlled benchmark result.

- **MTTD (0.24ms)**: this is `time.time()` before/after a single in-process Python function call on an already-buffered log line. It's real (not fabricated), but it's not "real-time production detection latency" — it's function-call overhead. The README's framing ("sub-millisecond real-time detection latency") implies something the number doesn't support.
- **100% TPR / zero false negatives**: true, but only because the benchmark never sends a single benign request. Without a false-positive control group, this number is close to meaningless — a detector that fired on *everything* would also score 100% TPR.

**Fix**: reset state before a run, add a batch of legitimate/benign traffic to compute a real FP rate, run N trials and report a distribution, and rename MTTD to something honest like "detection processing time" unless you actually measure attack-occurrence-to-alert across a realistic pipeline.

### 5. The audit log's own secret is hardcoded

`detection-engine/config.py`: `HMAC_KEY = b"secureloop-merkle-integrity-secret-key-2026"`, committed in plaintext. Anyone with repo read access can recompute valid-looking HMACs, which defeats the "cryptographic non-repudiation" claim. This is literally a T1552 in your own security tool. Move it to an environment variable — and consider mentioning in your writeup that you found and fixed this yourself; that's a better story than pretending it wasn't there.

### 6. The feedback loop writes files but the content is generic

The mechanism genuinely works end-to-end (detector → subprocess → synthesizer → new files + audit entry), which is real plumbing. But look at a generated rule:

```yaml
patterns:
- pattern-either:
  - pattern: $REQ.query
  - pattern: $REQ.body
```

This matches almost any route handler in the codebase — it doesn't encode anything about the *specific* vulnerable construct that was actually exploited (e.g., string-interpolation into a DB call). Same for the generated Nuclei template: it just checks `GET {url} → status 200`, with no payload and no auth — it wouldn't actually catch a regression of the vulnerability it's named after.

**Fix**: parameterize the synthesizer by the actual matched pattern/route, not just the technique ID — e.g. for T1190, generate a Semgrep pattern that specifically matches template-literal interpolation into `db.all/run/get`, which is the thing you actually found.

---

## Smaller issues worth cleaning up

- `.gitignore` excludes `dist/` and `*.db`, but both are present in the repo — they were tracked before the ignore rule was added. `git rm -r --cached apps/target-app/dist apps/target-app/secureloop.db` and commit.
- `__pycache__/` is committed under `detection-engine/` — add `__pycache__/` and `*.pyc` to `.gitignore`.
- "Merkle" is the wrong term throughout — what's implemented is a hash chain (each entry links to the previous hash), not a Merkle tree (a branching structure). Real technique, wrong name; an interviewer who knows the difference will notice.
- No Dockerfile/docker-compose/Terraform exist anywhere, despite the README's architecture diagram implying a "signed container" deploy step and SLSA provenance. Either build a minimal Dockerfile + cosign step, or drop those specific claims — dropping is far less work and just as credible.

---

## Prioritized fix list

1. **Rewrite the README to match reality** — cut SLSA/Cosign/OpenTelemetry/"empirically gathered" language until it's true. Highest priority, lowest effort, biggest trust impact.
2. **Wire real Semgrep/Gitleaks/Conftest calls** into `run-shift-left.sh` using the configs you already wrote correctly.
3. **Add `.github/workflows/ci.yml`** running that script on every PR, failing on findings. This is what actually makes it "shift-left."
4. **Add unit tests for `rules.py` and `merkle_log.py`** — synthetic log lines, true positive *and* true negative cases. Currently zero tests exist for the Python detection layer.
5. **Fix the benchmark methodology** in `attack_cli.py` — reset state, add a benign-traffic control batch, multiple trials.
6. **Make at least one of the four self-labeled detections real** (privilege escalation is the easiest — compare requester role to target action independently in Python).
7. **Move `HMAC_KEY` to an env var.**
8. **Make the synthesized rules specific**, not generic `$REQ.query` catch-alls.
9. **Repo hygiene**: untrack `dist/`, `*.db`, `__pycache__/`.
10. **Rename "Merkle" → "hash chain"** throughout, or actually build a tree structure if you want to keep the name.

Items 1–3 are the ones I'd do before this goes anywhere near a job application. The rest strengthen it but won't sink you if left for later.
