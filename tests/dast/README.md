# Authenticated DAST

The scan runs against a live, deployed instance (the pipeline starts one with
Docker Compose). ZAP authenticates as `alice`, a normal user, so the scan
exercises authenticated pages.

```bash
# From the repository root, with the app running on http://localhost:8000
mkdir -p tests/dast/out
chmod -R 777 tests/dast
docker run --rm --network host \
  -v "$PWD/tests/dast:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap.yaml

# ZAP cannot reliably detect IDOR / missing role checks, so run the scripted
# authenticated checks as well. Exit 1 means a flaw is still exploitable.
python3 tests/dast/idor_check.py

# Apply the blocking policy to the JSON report (default: fail on High).
python3 tests/dast/check_report.py
```

Expected results:

| Stage | Vulnerable baseline | After fixes |
|---|---|---|
| `idor_check.py` | exit 1, 4 flaws | exit 0 |
| ZAP High alerts | SQLi (and possibly XSS) | none |
| `check_report.py` | exit 1 | exit 0 |

Evidence to keep: `zap-report.html`, `zap-report.json`, and the CI job log.
