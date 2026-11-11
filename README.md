# HelpDesk — DevSecOps project baseline

A ticket-management application with users, agents and admins, built for the
ING-5-SSIR DevSecOps project. It starts **deliberately vulnerable** and is
meant to be secured across the whole lifecycle: code, image, pipeline, secrets,
orchestration, DAST, observability and incident response.

> **This baseline is intentionally insecure.** Do not deploy it on the
> internet. All tests are performed against our own local/dedicated
> environment. Data and credentials are fake.

## Stack

| Layer | Choice |
|---|---|
| Backend | FastAPI (Python 3.12) |
| Database | PostgreSQL 16 |
| Frontend | Jinja2 server-rendered templates |
| Auth | Signed session cookie, roles `user` / `agent` / `admin` |
| Local run | Docker Compose |
| Orchestration | Kubernetes (kind) |
| CI | GitHub Actions (GitLab CI equivalent is straightforward) |
| SAST / SCA / secrets / IaC / image | Semgrep / Trivy / Gitleaks / Trivy config / Trivy image |
| DAST | OWASP ZAP (authenticated) + scripted authorization checks |
| Admission | Kyverno |
| Observability | JSON logs + Prometheus metrics + Grafana/Loki (optional) |

## Quick start

```bash
cp .env.example .env
# Edit .env and set a random local password
docker compose up -d --build
# http://localhost:8000
```

Demo accounts (fake):

| User | Password | Role |
|---|---|---|
| alice | alice123 | user |
| bob | bob123 | user |
| carol | carol123 | agent |
| dave | dave123 | admin |

The database schema and fake seed data are created automatically on first
start (`app/db.py`, `db/schema.sql`).

## Initial vulnerabilities

The register with reproduction steps, impact, fix and retest is in
[`docs/vulnerabilities.md`](docs/vulnerabilities.md).

| ID | Flaw | OWASP 2021 |
|---|---|---|
| V1 | SQL injection in ticket search | A03 Injection |
| V2 | Stored XSS in comments (`\|safe`) | A03 Injection |
| V3 | IDOR on tickets/comments | A01 Broken Access Control |
| V4 | Missing role check on `/admin` | A01 Broken Access Control |
| V5 | Hardcoded session signing key | A02/A07 |
| V6 | Vulnerable `python-multipart` | A06 Vulnerable Components |

Quick proof (with the app running):

```bash
# SQLi: alice sees all tickets
curl -c /tmp/hd.cookies -d 'username=alice&password=alice123' \
  http://localhost:8000/login
curl -s -b /tmp/hd.cookies \
  'http://localhost:8000/tickets?q=%27%20OR%201%3D1%29%20--'

# IDOR: alice reads bob's ticket
curl -s -b /tmp/hd.cookies http://localhost:8000/tickets/2

# V5: forge an admin session with the leaked key
COOKIE=$(docker run --rm -v "$PWD:/app" -w /app helpdesk-app \
  python scripts/forge_session.py 4)
curl -s -b "helpdesk_session=$COOKIE" http://localhost:8000/admin
```

## Security pipeline

`.github/workflows/security.yml` has five blocking gates plus an authenticated
DAST stage that runs after deployment:

1. **SAST** — Semgrep (`auto` + `ci/semgrep.yml`).
2. **Dependencies** — Trivy filesystem, High/Critical.
3. **Secrets** — Gitleaks on the full history.
4. **IaC** — Trivy config on `deploy/`.
5. **Image** — Trivy image, High/Critical.
6. **DAST** — Compose deploys the app, ZAP scans as `alice`, then
   `tests/dast/idor_check.py` and `check_report.py` enforce the policy.

**Expected on the baseline:** the pipeline is red. Gitleaks finds the
hardcoded key, Trivy finds the vulnerable dependency, and Semgrep finds the
SQL/XSS patterns. That is the required "before" evidence. Fix V5/V6 first to
unblock the later stages, then fix V1–V4 and re-run.

The blocking policy is documented in
[`docs/blocking-policy.md`](docs/blocking-policy.md): Critical never passes,
High blocks with a time-boxed exception, Medium blocks on `main`, Low is
reported.

## Kubernetes deployment (kind)

Prerequisites: Docker, `kind`, `kubectl`.

```bash
./scripts/deploy_kind.sh
# http://helpdesk.localhost:8080
```

The script creates the cluster, installs ingress-nginx and Kyverno, builds and
loads the image, creates the DB Secret **without writing it to git**, applies
the admission policies, the workloads, then default-deny + targeted network
allows.

Negative admission test:

```bash
kubectl apply -f tests/k8s/bad-pod.yaml
# Expected: denied by Kyverno (privileged, :latest, no limits, no seccomp)
```

Hardening highlights:

- Multi-stage image, non-root UID 10001, read-only root filesystem, drop ALL
  capabilities, seccomp `RuntimeDefault`, resource limits.
- RBAC: dedicated ServiceAccount, token automount disabled.
- Network: default-deny ingress/egress, then only ingress-nginx → app, app → DB,
  DNS.
- Kyverno `ClusterPolicy` in Enforce mode.
- Pod Security Admission `restricted` on the namespace.

## Observability

The app emits one JSON object per request with `request_id`, `user_id`,
`method`, `path`, `status`, `latency_ms`, and a `security.suspicious_request`
event for SQLi/XSS/traversal patterns. `/metrics` exposes Prometheus counters:

- `helpdesk_http_requests_total{status}`
- `helpdesk_auth_failures_total`
- `helpdesk_suspicious_requests_total{pattern}`

Replay an attack and check:

```bash
curl -s 'http://localhost:8000/tickets?q=%27%20OR%201%3D1%29%20--' \
  -b /tmp/hd.cookies >/dev/null
docker compose logs app | grep security.suspicious_request
curl -s http://localhost:8000/metrics | grep suspicious
```

The detection/response plan is in
[`docs/incident-response.md`](docs/incident-response.md).

## Repository layout

```
app/                 FastAPI application, routes, templates, detection, metrics
db/schema.sql        PostgreSQL schema
deploy/manifests/    Namespace, app, DB, service, ingress, ServiceAccount
deploy/network/      Default-deny + targeted NetworkPolicies
deploy/policies/     Kyverno admission policy
deploy/kind/         kind cluster config
tests/dast/          ZAP automation, scripted authz checks, report gate
tests/k8s/           Negative admission test (bad pod)
ci/semgrep.yml       Project-specific SAST rules
scripts/             kind deployment, secret creation, session-forgery PoC
docs/                Threat model, vuln register, policy, IR, demo, evidence
```

## Documentation index

| Document | Purpose |
|---|---|
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE + OWASP mapping, DFD, assets |
| [`docs/vulnerabilities.md`](docs/vulnerabilities.md) | Six flaws: before/after, evidence, fix |
| [`docs/blocking-policy.md`](docs/blocking-policy.md) | Severity thresholds and exceptions |
| [`docs/secrets-rotation.md`](docs/secrets-rotation.md) | Revoke → purge → verify |
| [`docs/incident-response.md`](docs/incident-response.md) | Detect/contain/eradicate/recover/learn |
| [`docs/demo-script.md`](docs/demo-script.md) | 10–12 minute defense script |
| [`docs/evidence/README.md`](docs/evidence/README.md) | Evidence naming and rules |

## Suggested fix order

1. **V5 (secret)** — rotate the key, move it to a Secret, then purge history.
2. **V6 (dependency)** — upgrade `python-multipart` and `jinja2`, rebuild.
3. **V4 (admin role)** — add `require_admin` to both admin routes.
4. **V3 (IDOR)** — add object-level authorization to detail and comment.
5. **V1 (SQLi)** — parameterise the search query.
6. **V2 (XSS)** — remove `|safe`, add CSP.
7. Re-run `tests/dast/idor_check.py`, ZAP, Trivy, Gitleaks; keep the evidence.
8. Tag the fixed version (`v1-fixed`) and keep `v0-vulnerable` for the demo.

## Acceptance checklist (from §9 of the brief)

- [ ] App runs, containerized and hardened, on the orchestrator.
- [ ] A pushed secret or a critical vulnerability fails the pipeline.
- [ ] The secret scanner finds nothing in the full history.
- [ ] A non-compliant pod is rejected by admission control.
- [ ] The authenticated DAST confirms the flaws, then no longer finds them.
- [ ] An attack appears in telemetry and triggers the IR plan.
- [ ] The report fixes and traces every flaw and states its limits.

## Notes

- **No real secrets or personal data.** The hardcoded key is fake and exists
  only to be detected and rotated.
- **AI usage:** if AI assisted the code or documentation, declare what it
  produced and what the team validated, as required by §6.
- **Legal:** only test systems you own. Attacking anything else is illegal
  (Tunisian Penal Code art. 199 bis et seq.; Budapest Convention).
