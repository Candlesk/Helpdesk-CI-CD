from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from app.auth import get_current_user
from app.db import execute, query, query_one
from app.detection import detect
from app.logging_utils import log_event
from app.metrics import record_suspicious
from app.templates import render

router = APIRouter()


@router.get("/tickets")
def list_tickets(request: Request, q: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # VULN V1 (SQL injection): q is interpolated directly into the SQL string.
    # The "owner_id" filter can be removed with a payload such as
    #   ' OR 1=1 --
    term = f"%{q}%"
    if user["role"] == "user":
        where = (
            f"(t.subject ILIKE '{term}' OR t.body ILIKE '{term}') "
            f"AND t.owner_id = {user['id']}"
        )
    else:
        where = f"(t.subject ILIKE '{term}' OR t.body ILIKE '{term}')"

    tickets = query(
        "SELECT t.*, u.username AS owner FROM tickets t "
        "JOIN users u ON u.id = t.owner_id "
        f"WHERE {where} ORDER BY t.id DESC"
    )
    return render(request, "tickets.html", tickets=tickets, q=q)


@router.get("/tickets/{ticket_id}")
def ticket_detail(request: Request, ticket_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # VULN V3 (IDOR / broken object-level authorization): the ticket is loaded
    # by id only.  Any authenticated user can read any ticket, including the
    # internal agent comments below.
    ticket = query_one(
        "SELECT t.*, u.username AS owner FROM tickets t "
        "JOIN users u ON u.id = t.owner_id WHERE t.id = %s",
        (ticket_id,),
    )
    if not ticket:
        return render(request, "not_found.html", status_code=404)

    comments = query(
        "SELECT c.*, u.username AS author FROM comments c "
        "JOIN users u ON u.id = c.author_id "
        "WHERE c.ticket_id = %s ORDER BY c.id",
        (ticket_id,),
    )
    return render(request, "ticket_detail.html", ticket=ticket, comments=comments)


@router.post("/tickets")
def create_ticket(
    request: Request,
    subject: str = Form(...),
    body: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    execute(
        "INSERT INTO tickets (owner_id, subject, body) VALUES (%s, %s, %s)",
        (user["id"], subject, body),
    )
    return RedirectResponse("/tickets", status_code=303)


@router.post("/tickets/{ticket_id}/comments")
def add_comment(
    request: Request,
    ticket_id: int,
    body: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # VULN V3 (IDOR): no check that the current user owns the ticket.
    # VULN V2 (stored XSS): the body is rendered with |safe in the template.
    pattern = detect(body)
    if pattern:
        record_suspicious(pattern)
        log_event(
            "security.stored_payload",
            level="warning",
            request_id=getattr(request.state, "request_id", None),
            pattern=pattern,
            ticket_id=ticket_id,
            user_id=user["id"],
        )

    execute(
        "INSERT INTO comments (ticket_id, author_id, body) VALUES (%s, %s, %s)",
        (ticket_id, user["id"], body),
    )
    return RedirectResponse(f"/tickets/{ticket_id}", status_code=303)
