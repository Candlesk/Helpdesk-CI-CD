"""Session helpers.

Authentication is a signed cookie handled by Starlette's SessionMiddleware.
The signing key is the hardcoded value from app/config.py (VULN V5).
"""

from fastapi import Request

from app.db import query_one


def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return query_one(
        "SELECT id, username, role, full_name FROM users WHERE id = %s",
        (user_id,),
    )


def is_agent_or_admin(user) -> bool:
    return bool(user) and user["role"] in ("agent", "admin")
