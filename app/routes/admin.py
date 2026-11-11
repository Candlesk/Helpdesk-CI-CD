from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from app.auth import get_current_user
from app.db import execute, query
from app.logging_utils import log_event
from app.templates import render

router = APIRouter()

VALID_ROLES = {"user", "agent", "admin"}


@router.get("/admin")
def admin_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # VULN V4 (broken function-level authorization): only authentication is
    # checked, not the role.  Any logged-in user can open /admin and see every
    # account, including the administrator.
    users = query("SELECT id, username, role, full_name FROM users ORDER BY id")
    return render(request, "admin.html", users=users)


@router.post("/admin/users/{user_id}/role")
def update_role(
    request: Request,
    user_id: int,
    role: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # VULN V4: no role check either.  A normal user can promote themselves to
    # administrator with a single POST.
    if role not in VALID_ROLES:
        return RedirectResponse("/admin", status_code=303)

    execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
    log_event(
        "admin.role_changed",
        level="warning",
        request_id=getattr(request.state, "request_id", None),
        actor_id=user["id"],
        target_id=user_id,
        new_role=role,
    )
    return RedirectResponse("/admin", status_code=303)
