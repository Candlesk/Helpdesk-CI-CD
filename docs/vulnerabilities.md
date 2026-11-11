# Vulnerability register — HelpDesk

This is the "before" state of the application. Each flaw is intentional and
must be demonstrated, fixed, and retested. Keep the evidence files referenced
below in `docs/evidence/`.

> Scope note: all exploitation was performed against our own local instance.
> The data is fake. No real credentials or personal data are used.

## Summary

| ID | Vulnerability | Severity | OWASP 2021 | STRIDE | CWE | Status |
|---|---|---|---|---|---|---|
| V1 | SQL injection in ticket search | High | A03 Injection | Tampering, Info disclosure | CWE-89 | Open |
| V2 | Stored XSS in comments | High | A03 Injection | Tampering, Info disclosure | CWE-79 | Open |
| V3 | IDOR on tickets and comments | High | A01 Broken Access Control | Info disclosure, Elevation | CWE-639 | Open |
| V4 | Missing role check on `/admin` | Critical | A01 Broken Access Control | Elevation of privilege | CWE-862 | Open |
| V5 | Hardcoded session signing key | Critical | A02 Cryptographic Failures / A07 Auth Failures | Spoofing | CWE-798 | Open |
| V6 | Vulnerable dependency (`python-multipart`) | High | A06 Vulnerable Components | DoS, Tampering | CWE-1104 | Open |

---

## V1 — SQL injection in ticket search

- **Location:** `app/routes/tickets.py`, `list_tickets()`
- **Cause:** the `q` parameter is interpolated into the SQL string with an
  f-string. The query is executed with no parameters, so the database parses
  the user input as SQL.
- **Impact:** a normal user can remove the `owner_id` filter and read every
  ticket, including internal agent comments (MFA codes, salary data). The same
  injection point can be used for `UNION`-based extraction of the `users`
  table (usernames and password hashes).
- **Reproduction:**

  ```bash
  # Log in as alice (normal user)
  curl -c /tmp/hd.cookies -d 'username=alice&password=alice123' \
    http://localhost:8000/login

  # Baseline: alice sees only her 2 tickets
  curl -s -b /tmp/hd.cookies 'http://localhost:8000/tickets?q=VPN'

  # Exploit: the closing parenthesis balances the query, -- comments the rest
  curl -s -b /tmp/hd.cookies \
    'http://localhost:8000/tickets?q=%27%20OR%201%3D1%29%20--'
  # Alice now sees tickets 1-4, including Bob's payroll ticket.
  ```

- **Evidence:** `docs/evidence/v1-before.png` (or `.txt` with request/response)
- **Fix:** parameterise the query. Never build SQL with interpolation:

  ```python
  sql = (
      "SELECT t.*, u.username AS owner FROM tickets t "
      "JOIN users u ON u.id = t.owner_id "
      "WHERE (t.subject ILIKE %s OR t.body ILIKE %s)"
  )
  params = [f"%{q}%", f"%{q}%"]
  if user["role"] == "user":
      sql += " AND t.owner_id = %s"
      params.append(user["id"])
  sql += " ORDER BY t.id DESC"
  tickets = query(sql, tuple(params))
  ```

- **Retest:** `python3 tests/dast/idor_check.py` (SQLi check must be OK);
  ZAP must no longer report SQL injection.
- **Status:** [ ] fixed [ ] retested

---

## V2 — Stored XSS in ticket comments

- **Location:** `app/templates/ticket_detail.html` — `{{ c.body | safe }}`;
  input stored raw in `app/routes/tickets.py`, `add_comment()`.
- **Cause:** Jinja autoescaping is explicitly disabled with the `|safe` filter.
- **Impact:** any authenticated user can store JavaScript that executes in the
  browser of every user who opens the ticket, including agents and admins.
  This enables session-riding actions, phishing, keylogging and worm-like
  propagation. (The session cookie is HttpOnly, which limits direct cookie
  theft but does not prevent actions performed as the victim.)
- **Reproduction:**

  ```bash
  curl -b /tmp/hd.cookies \
    --data-urlencode "body=<script>alert('XSS')</script>" \
    http://localhost:8000/tickets/1/comments

  # Open http://localhost:8000/tickets/1 in a browser: the alert fires.
  ```

- **Evidence:** `docs/evidence/v2-before.png`
- **Fix:** remove `|safe` (rely on autoescaping). If rich text is required,
  sanitise with an allow-list library (e.g. `bleach`) and add a strict CSP:

  ```python
  # middleware, after the response is built
  response.headers["Content-Security-Policy"] = (
      "default-src 'self'; script-src 'self'; object-src 'none'; "
      "base-uri 'self'; frame-ancestors 'none'"
  )
  ```

- **Retest:** post the payload again; the page must contain
  `&lt;script&gt;` and no executable `<script>`. `idor_check.py` XSS check OK.
- **Status:** [ ] fixed [ ] retested

---

## V3 — IDOR on tickets and comments

- **Location:** `app/routes/tickets.py`, `ticket_detail()` and `add_comment()`
- **Cause:** the ticket is selected by `id` only. There is no check that the
  current user owns it (or is an agent/admin).
- **Impact:** any authenticated user reads any ticket by changing the number in
  the URL, including internal comments containing salary and MFA data. They can
  also post comments on other users' tickets.
- **Reproduction:**

  ```bash
  # Alice is user id 1; ticket 2 belongs to Bob.
  curl -s -b /tmp/hd.cookies http://localhost:8000/tickets/2
  # The page shows "Payroll portal shows the wrong salary" and the HR comment.
  ```

- **Evidence:** `docs/evidence/v3-before.png`
- **Fix:** enforce object-level authorisation on every access:

  ```python
  ticket = query_one("SELECT ... WHERE t.id = %s", (ticket_id,))
  if not ticket:
      return render(request, "not_found.html", status_code=404)
  if user["role"] == "user" and ticket["owner_id"] != user["id"]:
      raise HTTPException(status_code=403, detail="Forbidden")
  ```

  Apply the same check in `add_comment()`. Prefer a single helper
  (`get_ticket_or_403(user, ticket_id)`) so the rule cannot be forgotten.
- **Retest:** `idor_check.py` IDOR check OK; alice gets 403/404 for ticket 2.
- **Status:** [ ] fixed [ ] retested

---

## V4 — Missing role check on the admin area

- **Location:** `app/routes/admin.py`, `admin_page()` and `update_role()`
- **Cause:** both handlers check that a user is authenticated, but never check
  `user["role"] == "admin"`.
- **Impact:** any logged-in user opens `/admin`, enumerates all accounts, and
  promotes themselves to administrator. This is a full privilege escalation.
- **Reproduction:**

  ```bash
  # As alice (normal user)
  curl -s -b /tmp/hd.cookies http://localhost:8000/admin
  curl -b /tmp/hd.cookies -d 'role=admin' \
    http://localhost:8000/admin/users/1/role
  # Reload /tickets: the Admin link now appears.
  ```

- **Evidence:** `docs/evidence/v4-before.png`
- **Fix:** require the admin role on every admin route, ideally as a shared
  dependency so it cannot be forgotten:

  ```python
  def require_admin(request: Request):
      user = get_current_user(request)
      if not user or user["role"] != "admin":
          raise HTTPException(status_code=403, detail="Forbidden")
      return user
  ```

  Add a server-side audit event for every role change and test that a normal
  user receives 403.
- **Retest:** `idor_check.py` admin check OK; alice receives 403.
- **Status:** [ ] fixed [ ] retested

---

## V5 — Hardcoded session signing key

- **Location:** `app/config.py` — `SECRET_KEY`
- **Cause:** the key used by Starlette's `SessionMiddleware` is committed to
  the repository. Anyone with read access to the source can sign a session
  cookie for any user id.
- **Impact:** complete account takeover, including administrator. No password
  or MFA is needed. The key is also in the git history, so deleting the line
  is not enough: the key must be rotated.
- **Reproduction:**

  ```bash
  # Forge a cookie for user 4 (dave, admin) using the leaked key
  COOKIE=$(docker run --rm -v "$PWD:/app" -w /app helpdesk-app \
    python scripts/forge_session.py 4)

  curl -s -b "helpdesk_session=$COOKIE" http://localhost:8000/admin \
    | grep -E 'Dave Gharbi|User administration'
  # Access granted without any login.
  ```

- **Evidence:** `docs/evidence/v5-before.txt`
- **Fix (order matters):**
  1. **Revoke first:** rotate the key at the source. Generate 32+ random bytes
     (`openssl rand -base64 48`) and store them in the secret manager
     (Kubernetes Secret / Sealed Secret / Vault). All existing sessions become
     invalid.
  2. **Then purge:** remove the value from git history
     (`git filter-repo` / BFG), force-push, ask everyone to re-clone.
  3. **Verify:** `gitleaks detect --source . --log-opts="--all"` → 0 findings.
  4. Fail closed in code:

  ```python
  SECRET_KEY = os.environ["SECRET_KEY"]  # KeyError if missing: do not start
  ```

- **Retest:** the old forged cookie is rejected (redirect to `/login`), and the
  full-history Gitleaks scan is clean.
- **Status:** [ ] fixed [ ] retested

See `docs/secrets-rotation.md` for the exact command sequence.

---

## V6 — Vulnerable dependency

- **Location:** `requirements.txt`
  - `python-multipart==0.0.6` — CVE-2024-24762 (HIGH, ReDoS) and newer
    multipart parsing CVEs reported by Trivy.
  - `jinja2==3.1.2` — medium-severity template CVEs (fixed in 3.1.6).
- **Cause:** dependencies were pinned to old versions and never scanned.
- **Impact:** denial of service via a crafted `multipart/form-data` body;
  depending on the CVE, file write/path traversal or template injection.
- **Reproduction:**

  ```bash
  docker run --rm -v "$PWD:/repo" aquasec/trivy:latest \
    fs --scanners vuln --exit-code 1 --severity HIGH,CRITICAL /repo
  # 5 HIGH findings in python-multipart 0.0.6
  ```

- **Evidence:** `docs/evidence/v6-before.txt` (Trivy output)
- **Fix:** upgrade to the fixed versions and rebuild:

  ```text
  python-multipart==0.0.30
  jinja2==3.1.6
  ```

  Then rebuild the image and re-scan both the filesystem and the image. Add
  Dependabot/Renovate so this does not regress.
- **Retest:** Trivy reports 0 HIGH/CRITICAL for the project dependencies and
  the image.
- **Status:** [ ] fixed [ ] retested

---

## Known gaps (acknowledge in the report)

These are not part of the initial six but must be discussed honestly:

- No CSRF tokens on state-changing forms (SameSite=Lax reduces but does not
  eliminate the risk).
- No login rate limiting / lockout (brute force is only detected, not blocked).
- The local ingress serves HTTP; the session cookie is not `Secure` in the
  demo. Production must terminate TLS and set `https_only=True`.
- No MFA for agents/admins.
- Logs are process-local; in a multi-replica deployment they must be shipped
  to Loki/ELK and metrics must use `prometheus_client` multiprocess mode.
- ZAP cannot prove the absence of business-logic flaws; the scripted checks
  cover only the four known authorization cases.
