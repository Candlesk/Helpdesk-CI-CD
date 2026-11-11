#!/usr/bin/env python3
"""Authenticated authorization checks that ZAP cannot reliably detect.

ZAP is good at injection/XSS, but IDOR and missing function-level
authorization need a scripted request.  This script logs in as alice (a
normal user) and asserts the *secure* behaviour:

  - alice cannot read bob's ticket                 (IDOR)
  - alice cannot list other users' tickets via SQLi
  - alice cannot open /admin                       (broken function authz)
  - a <script> comment is escaped, not executed    (stored XSS)

Exit code 0 = all checks secure, 1 = at least one flaw still exploitable.
"""

import http.cookiejar
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
PAYLOAD = "<script>alert('dast')</script>"
results = []


def new_session():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def login(opener, username, password):
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    request = urllib.request.Request(BASE_URL + "/login", data=data, method="POST")
    opener.open(request)


def get(opener, path):
    try:
        response = opener.open(BASE_URL + path)
        return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def post(opener, path, fields):
    data = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(BASE_URL + path, data=data, method="POST")
    try:
        response = opener.open(request)
        return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def check(name, vulnerable, detail):
    results.append((name, vulnerable, detail))
    state = "VULNERABLE" if vulnerable else "OK"
    print(f"[{state}] {name}: {detail}")


alice = new_session()
login(alice, "alice", "alice123")

# 1. IDOR: ticket 2 belongs to bob.
status, body = get(alice, "/tickets/2")
check(
    "IDOR (read another user's ticket)",
    status == 200 and "Payroll portal" in body,
    f"GET /tickets/2 -> {status}",
)

# 2. SQL injection bypasses the owner filter.
sqli = urllib.parse.quote("' OR 1=1) --")
status, body = get(alice, f"/tickets?q={sqli}")
check(
    "SQL injection (owner filter bypass)",
    status == 200 and "Payroll portal" in body,
    f"GET /tickets?q={sqli} -> {status}",
)

# 3. Broken function-level authorization.
status, body = get(alice, "/admin")
check(
    "Broken function-level authorization (/admin)",
    status == 200 and "User administration" in body,
    f"GET /admin -> {status}",
)

# 4. Stored XSS: post a script as alice on her own ticket, then read it back.
status, _ = post(alice, "/tickets/1/comments", {"body": PAYLOAD})
status, body = get(alice, "/tickets/1")
check(
    "Stored XSS (unescaped comment)",
    PAYLOAD in body,
    f"POST comment -> {status}; raw <script> present={PAYLOAD in body}",
)

failed = [name for name, vulnerable, _ in results if vulnerable]
if failed:
    print(f"\nFAIL: {len(failed)} flaw(s) still exploitable: {', '.join(failed)}")
    sys.exit(1)

print("\nPASS: all authenticated authorization checks are secure.")
