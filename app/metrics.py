"""Minimal Prometheus metrics, no extra dependency.

Counters live in process memory.  That is enough for the demo; in a real
deployment use prometheus_client and a multi-process mode.
"""

import threading
from collections import defaultdict

_lock = threading.Lock()
_requests = defaultdict(int)
_auth_failures = 0
_suspicious = defaultdict(int)


def record_request(status: int) -> None:
    with _lock:
        _requests[str(status)] += 1


def record_auth_failure() -> None:
    global _auth_failures
    with _lock:
        _auth_failures += 1


def record_suspicious(pattern: str) -> None:
    with _lock:
        _suspicious[pattern] += 1


def render() -> str:
    lines = [
        "# HELP helpdesk_http_requests_total HTTP requests by status code.",
        "# TYPE helpdesk_http_requests_total counter",
    ]
    with _lock:
        for status, count in sorted(_requests.items()):
            lines.append(f'helpdesk_http_requests_total{{status="{status}"}} {count}')

        lines += [
            "# HELP helpdesk_auth_failures_total Failed login attempts.",
            "# TYPE helpdesk_auth_failures_total counter",
            f"helpdesk_auth_failures_total {_auth_failures}",
            "# HELP helpdesk_suspicious_requests_total Requests matching an attack pattern.",
            "# TYPE helpdesk_suspicious_requests_total counter",
        ]
        for pattern, count in sorted(_suspicious.items()):
            lines.append(
                f'helpdesk_suspicious_requests_total{{pattern="{pattern}"}} {count}'
            )
    return "\n".join(lines) + "\n"
