# Defense demo script (~10–12 minutes)

Rehearse this twice. Keep two terminals: one for commands, one for logs
(`docker compose logs -f app`). Have the evidence folder open.

## 0. Context (30 s)

"This is HelpDesk, a ticket app with users, agents and admins. We started from
a deliberately vulnerable version, tagged `v0-vulnerable`, and hardened it
across the whole lifecycle. The report maps six initial flaws to OWASP 2021."

Show the architecture diagram and the acceptance checklist.

## 1. The application works (1 min)

```bash
docker compose up -d --build
# http://localhost:8000
```

Log in as `alice / alice123`. Show her two tickets. Log in as `carol / carol123`
(agent) and show all tickets + internal comments. This proves roles and
sensitive data exist.

## 2. Exploit the vulnerable version (3 min)

```bash
git checkout v0-vulnerable   # or use the tagged image
docker compose up -d --build
```

As alice:

1. **SQLi** — open
   `http://localhost:8000/tickets?q=%27%20OR%201%3D1%29%20--`
   Bob's payroll ticket appears. Point at the `security.suspicious_request`
   log line and the metrics counter.
2. **IDOR** — open `http://localhost:8000/tickets/2`. The HR comment with the
   salary is visible.
3. **Stored XSS** — post `<script>alert('XSS')</script>` on ticket 1 and reload.
4. **Broken role check** — open `http://localhost:8000/admin` as alice, promote
   alice to admin.
5. **Hardcoded key** — forge a session for dave:

   ```bash
   COOKIE=$(docker run --rm -v "$PWD:/app" -w /app helpdesk-app \
     python scripts/forge_session.py 4)
   curl -s -b "helpdesk_session=$COOKIE" http://localhost:8000/admin
   ```

   Admin access without a password.

## 3. Pipeline blocks (2 min)

Show the CI run for the vulnerable commit:

- `secrets` fails: Gitleaks finds the hardcoded `SECRET_KEY`.
- `dependencies` fails: Trivy finds HIGH CVEs in `python-multipart==0.0.6`.
- `sast` fails: the custom Semgrep rule flags the f-string SQL and `|safe`.
- `iac` fails if you temporarily apply `tests/k8s/bad-pod.yaml` (or show the
  Trivy config output).

Then show the **blocking policy** slide: Critical never, High ≤ 14 days with
ticket + compensating control, Medium blocks on `main`.

## 4. Deployment hardening (2 min)

```bash
./scripts/deploy_kind.sh
kubectl apply -f tests/k8s/bad-pod.yaml
# Expected: admission webhook denies the request (privileged / latest tag /
# no limits / no seccomp).
```

Show:

```bash
kubectl -n helpdesk get pods
kubectl -n helpdesk describe pod -l app.kubernetes.io/component=app | \
  grep -E 'RunAsNonRoot|ReadOnlyRootFilesystem|Seccomp|Drop'
kubectl -n helpdesk get networkpolicy
```

Apply default-deny, show the app unreachable, then apply the targeted allows
and show it reachable again. (The deploy script does this automatically.)

## 5. Fixes and re-scan (1 min)

```bash
git checkout main   # fixed version
docker compose up -d --build
python3 tests/dast/idor_check.py     # exit 0
python3 tests/dast/check_report.py   # no High findings
gitleaks detect --source . --log-opts="--all"   # 0 leaks
```

Show the green pipeline and the before/after table.

## 6. Detection and response (2 min)

Replay the SQLi on the fixed version (it returns no data) and show:

- the structured log event,
- `helpdesk_suspicious_requests_total{pattern="sqli"}`,
- the `SQLiAttempt` alert in Grafana/Prometheus.

Walk the IR plan: detect → contain (block IP + rotate key) → eradicate (patch)
→ recover (health + journey) → learn (post-mortem + regression test).

## 7. Honest limitations (30 s)

"We do not claim the app is unbreakable. ZAP cannot see business-logic flaws,
SCA only knows published CVEs, and our detector is a high-signal signature, not
a WAF. The report lists these limits."

## Fallback plan

- If the cluster is slow: show recorded `kubectl` output and screenshots; keep
  the live demo on Docker Compose.
- If the network is unavailable: pre-pull images, pre-build the image, and use
  the saved ZAP/Trivy reports.
- If a demo step fails, state the expected result and show the evidence file;
  do not improvise destructive commands.
