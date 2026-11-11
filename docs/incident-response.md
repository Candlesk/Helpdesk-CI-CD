# Incident-response plan — HelpDesk

This plan is exercised at least once during the project: replay an attack,
show it in the telemetry, and walk through the five phases below.

## 1. Detection signals

| Signal | Source | Example |
|---|---|---|
| SQLi/XSS/traversal pattern | `security.suspicious_request` log event | `pattern=sqli`, `path=/tickets`, `query=...` |
| Repeated failed logins | `auth.login_failed` events, `helpdesk_auth_failures_total` | > 20 failures / 5 min from one IP |
| Forbidden access spike | `helpdesk_http_requests_total{status="403"}` | many 403s for one user |
| Role change | `admin.role_changed` event | unexpected promotion to `admin` |
| Container/network anomaly | Kubernetes events, netpol denies | unexpected egress attempt |
| Vulnerability finding | CI security job | new Critical/High on `main` |

Starter Prometheus alert:

```yaml
groups:
  - name: helpdesk-security
    rules:
      - alert: SQLiAttempt
        expr: increase(helpdesk_suspicious_requests_total{pattern="sqli"}[5m]) > 0
        labels: { severity: high }
        annotations:
          summary: "SQL injection pattern detected"
      - alert: BruteForce
        expr: increase(helpdesk_auth_failures_total[5m]) > 20
        labels: { severity: high }
        annotations:
          summary: "More than 20 failed logins in 5 minutes"
```

Loki query for the demo:

```logql
{app="helpdesk"} | json | event="security.suspicious_request"
```

## 2. Severity

| Level | Definition | Response |
|---|---|---|
| SEV-1 | Confirmed data breach, admin takeover, signing key leak | Immediate containment, all hands, notify supervisor |
| SEV-2 | Exploitable High finding on a live environment | Contain within 1 hour, fix same day |
| SEV-3 | Attempt detected but blocked/no evidence of success | Investigate, tune detection, fix within the sprint |
| SEV-4 | Low/informational | Backlog |

## 3. Roles

| Role | Responsibility |
|---|---|
| Incident commander | Runs the timeline, makes decisions, owns communication |
| Investigator | Analyses logs, reproduces the attack, determines scope |
| Remediator | Patches, redeploys, rotates credentials |
| Scribe | Records timestamps, actions, evidence hashes |
| Communications | Updates the supervisor/team; no speculation |

For a 3–4 person team, combine roles but write down who held which role.

## 4. Phases

### Detect

1. Confirm the alert is not a false positive: find the matching log line and
   the request id.
2. Capture the raw evidence **before** changing anything: log excerpt,
   request/response, metric graph, pod/node identity.
3. Open an incident ticket with a timestamp and severity.

### Contain

1. Block the source at the ingress (deny-list / rate limit) or isolate the pod
   with a NetworkPolicy.
2. If a session or key is suspected: rotate `SECRET_KEY` and redeploy. This
   invalidates all sessions.
3. If the database is at risk: revoke the app's DB credentials and rotate them.
4. Preserve evidence: do not delete pods/logs until the timeline is captured.

### Eradicate

1. Identify the root cause (e.g. V1 string interpolation).
2. Patch, add a regression test, and rebuild the image.
3. Re-run the blocking pipeline and the DAST checks.

### Recover

1. Redeploy the fixed version; confirm `/healthz` and a normal user journey.
2. Monitor the detection signals for at least 30 minutes.
3. Re-enable traffic progressively; keep the block on the attacker IP.

### Learn

1. Write a blameless post-mortem: timeline, root cause, impact, what worked,
   what failed.
2. Add a detection or test that would have caught it earlier.
3. Update this plan and the threat model.
4. Close the incident ticket with links to evidence.

## 5. Runbook — SQL injection (the demo scenario)

1. **Replay** as alice:

   ```bash
   curl -c /tmp/ir.cookies -d 'username=alice&password=alice123' \
     http://localhost:8000/login
   curl -b /tmp/ir.cookies \
     'http://localhost:8000/tickets?q=%27%20OR%201%3D1%29%20--'
   ```

2. **Detect:** the response returns Bob's payroll ticket; the app logs:

   ```json
   {"event":"security.suspicious_request","pattern":"sqli","path":"/tickets",...}
   ```

   `helpdesk_suspicious_requests_total{pattern="sqli"}` increments. The
   Prometheus alert `SQLiAttempt` fires.

3. **Contain:** apply a temporary ingress deny for the source IP and rotate the
   session key (invalidates any stolen session). Example (kind/nginx):

   ```bash
   kubectl -n ingress-nginx annotate ingress helpdesk \
     nginx.ingress.kubernetes.io/denylist "10.0.0.5" --overwrite
   ```

4. **Eradicate:** apply the parameterised-query fix, rebuild, redeploy.

5. **Recover:** verify alice can only see her tickets, the payload returns no
   data, and the ZAP/scripted checks are clean.

6. **Learn:** add the SQLi payload to the regression checks (already in
   `tests/dast/idor_check.py`), and keep the alert.

## 6. Evidence checklist

- [ ] Alert screenshot / metric graph
- [ ] Matching structured log line(s), with request id
- [ ] Raw attack request and response
- [ ] Timeline with timestamps and actor
- [ ] Fix commit and green pipeline
- [ ] Post-mortem note

## 7. Legal scope

All offensive actions are performed **only** against our own application, on
a local or dedicated environment. Attacking a system we do not own is illegal
(Tunisian Penal Code, art. 199 bis et seq.; Budapest Convention).
