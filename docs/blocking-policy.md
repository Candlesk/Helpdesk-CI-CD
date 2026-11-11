# Blocking policy — security pipeline

This document is the written policy required by §4.3 of the brief. It defines
what fails the build, why, and how an exception is granted.

## 1. Controls in the pipeline

| Control | Tool | Scope | Job |
|---|---|---|---|
| Static analysis (SAST) | Semgrep (`auto` + project rules) | Python and Jinja templates | `sast` |
| Dependencies (SCA) | Trivy filesystem | `requirements.txt`, lockfiles | `dependencies` |
| Secrets | Gitleaks | Full git history and working tree | `secrets` |
| IaC | Trivy config | `deploy/` Kubernetes manifests | `iac` |
| Container image | Trivy image | Built image (OS + Python packages) | `image` |
| DAST | ZAP + scripted checks | Live, authenticated instance | `dast` |

All jobs are blocking (`allow_failure: false` in GitLab terms; a failing step
in GitHub Actions). There is no `continue-on-error` on a security job.

## 2. Severity thresholds

| Severity | Pipeline action | Rationale |
|---|---|---|
| **Critical** | **Block. No exception.** | Trivially exploitable and reaches sensitive ticket data or the signing key. A Critical finding is never accepted for this project. |
| **High** | **Block.** Exception possible only under the process below, ≤ 14 days. | Exploitable with public tooling; the data includes payroll/MFA notes. An upstream fix usually exists. |
| **Medium** | **Warn on pull request, block on `main` before delivery.** | Real but requires more preconditions. Fixing before the final tag is realistic for a 6-week project. |
| **Low** | Report only. | Low exploitability in this context; fixing everything would consume the project budget. |

These thresholds are deliberately not "everything blocks": a pipeline that
fails on informational findings gets bypassed by the team, which is worse than
a focused policy. The justification is based on **exploitability × data
sensitivity**, not on an arbitrary number.

## 3. Exceptions

An exception is a time-boxed risk acceptance, not a mute button.

Required for every exception:

1. A ticket/issue with the finding ID, CVE/rule, affected component, and
   exploitability analysis.
2. A compensating control (e.g. the vulnerable endpoint is not reachable from
   the internet, or a WAF rule blocks the payload).
3. A named owner and an **expiry date ≤ 14 days**.
4. Approval by the security lead (a different person from the author).
5. A line in the ignore file with the ticket and expiry, e.g.:

   ```text
   # .trivyignore
   # CVE-2026-XXXXX — no upstream fix; app not exposed to multipart uploads
   # owner: carol — expires: 2026-12-01 — ticket: SEC-42
   CVE-2026-XXXXX
   ```

   For Semgrep use `# nosemgrep: rule-id` with the same comment; for Gitleaks
   use an allowlist entry only for fake/example files, never for real secrets.

Expired exceptions fail the pipeline automatically because the ignore entry is
removed at expiry during the weekly review.

## 4. What the policy does NOT prove

- It does not prove the absence of vulnerabilities. SAST and DAST have blind
  spots: business logic, authorization semantics, race conditions, and
  multi-step attacks.
- ZAP cannot reliably find IDOR or missing role checks; the scripted
  `tests/dast/idor_check.py` covers only the four known cases.
- SCA reports known CVEs, not malicious packages or zero-days.
- The image scan covers the OS and Python packages, not the application logic.
- A green pipeline is a baseline, not a security guarantee. The report must
  include this limitation explicitly.

## 5. Evidence

For the defense, keep:

- A red pipeline caused by a pushed fake secret (`secrets` job).
- A red pipeline caused by the vulnerable `python-multipart` version
  (`dependencies` and `image` jobs).
- A red pipeline caused by the SQLi rule (`sast` job).
- A red pipeline caused by a bad manifest (`iac` job).
- The green pipeline after all fixes.
