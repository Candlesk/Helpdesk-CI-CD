"""Application configuration.

VULN V5 (hardcoded secret): the session signing key is committed to the
repository.  This lets anyone who reads the source forge a signed session
cookie for any user id, including an administrator.

Fix: read the key from the environment / secret store and fail closed when it
is missing.  Never keep a usable default in the code.
"""

import os

# VULN V5 -- intentionally hardcoded, detected by Gitleaks.
SECRET_KEY = "hd_live_51H8xQ2eZvKYlo2C7uVw"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://helpdesk:helpdesk@localhost:5432/helpdesk",
)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")
