from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from app.db import query_one
from app.logging_utils import log_event
from app.metrics import record_auth_failure
from app.security import verify_password
from app.templates import render

router = APIRouter()


@router.get("/login")
def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/tickets", status_code=303)
    return render(request, "login.html", error=None)


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = query_one(
        "SELECT id, username, password_hash, role, full_name FROM users WHERE username = %s",
        (username,),
    )
    if not user or not verify_password(password, user["password_hash"]):
        record_auth_failure()
        log_event(
            "auth.login_failed",
            level="warning",
            request_id=getattr(request.state, "request_id", None),
            username=username,
            source_ip=request.client.host if request.client else None,
        )
        return render(
            request,
            "login.html",
            status_code=401,
            error="Invalid username or password.",
        )

    request.session["user_id"] = user["id"]
    log_event(
        "auth.login_succeeded",
        request_id=getattr(request.state, "request_id", None),
        user_id=user["id"],
        role=user["role"],
    )
    return RedirectResponse("/tickets", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
