#!/usr/bin/env python3
"""Fail the pipeline when ZAP reports an alert at/above the policy threshold.

ZAP risk codes: 0=informational, 1=low, 2=medium, 3=high.
The blocking policy in docs/blocking-policy.md blocks High, so the default
threshold is 3.  Override with ZAP_FAIL_RISK=2 if you decide to block Medium.
"""

import json
import os
import pathlib
import sys

REPORT = pathlib.Path(os.environ.get("ZAP_REPORT", "tests/dast/zap-report.json"))
THRESHOLD = int(os.environ.get("ZAP_FAIL_RISK", "3"))

if not REPORT.exists():
    print(f"ZAP report not found: {REPORT}", file=sys.stderr)
    sys.exit(1)

data = json.loads(REPORT.read_text(encoding="utf-8"))
findings = []
for site in data.get("site", []):
    for alert in site.get("alerts", []):
        risk = int(alert.get("riskcode", 0))
        if risk >= THRESHOLD:
            findings.append(
                (
                    risk,
                    alert.get("alert", "unknown"),
                    alert.get("url", ""),
                    alert.get("solution", ""),
                )
            )

if findings:
    for risk, name, url, solution in findings:
        print(f"[FAIL risk={risk}] {name} — {url}")
        if solution:
            print(f"  fix: {solution}")
    print(f"\n{len(findings)} finding(s) at or above risk {THRESHOLD}.")
    sys.exit(1)

print(f"ZAP report: no findings at or above risk {THRESHOLD}.")
