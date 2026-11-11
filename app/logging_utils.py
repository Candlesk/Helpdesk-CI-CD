"""Structured JSON logging.

One JSON object per line, with a correlation id, so Loki/ELK can index the
fields directly.  Never pass passwords, cookies or raw personal data here.
"""

import json
import sys
from datetime import datetime, timezone


def log_event(event: str, level: str = "info", **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
    }
    record.update(fields)
    print(json.dumps(record, default=str, ensure_ascii=False), file=sys.stdout, flush=True)
