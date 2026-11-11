"""Very small signature detector used for the observability demo.

It is deliberately simple and high-signal: enough to prove that an attack
appears in telemetry and triggers the incident-response plan.  It is not a WAF.
"""

import re
from urllib.parse import unquote

PATTERNS = {
    "sqli": re.compile(
        r"(\bunion\b[\s\S]*\bselect\b|'\s*or\s*1\s*=\s*1|--\s|;\s*drop\s+table\b)",
        re.IGNORECASE,
    ),
    "xss": re.compile(r"(<script\b|onerror\s*=|javascript\s*:)", re.IGNORECASE),
    "traversal": re.compile(r"(\.\./|%2e%2e%2f)", re.IGNORECASE),
}


def detect(value: str) -> str | None:
    if not value:
        return None
    decoded = unquote(value)
    for name, pattern in PATTERNS.items():
        if pattern.search(decoded):
            return name
    return None
