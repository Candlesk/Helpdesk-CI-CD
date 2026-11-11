"""PostgreSQL access layer and demo seed data.

The application intentionally uses raw SQL.  The ticket search builds its
query by string interpolation (VULN V1); every other query is parameterised
so the difference is easy to show in the report.
"""

import time
from pathlib import Path

import psycopg2
import psycopg2.extras

from app.config import DATABASE_URL
from app.security import hash_password

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def _run(sql: str, params=None, fetch: bool = False):
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                if params is None:
                    cur.execute(sql)
                else:
                    cur.execute(sql, params)
                if fetch and cur.description:
                    return cur.fetchall()
                return None
    finally:
        conn.close()


def query(sql: str, params=None):
    return _run(sql, params, fetch=True) or []


def query_one(sql: str, params=None):
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params=None):
    _run(sql, params)


def init_db(retries: int = 30, delay: float = 2.0) -> None:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    for attempt in range(1, retries + 1):
        try:
            conn = get_conn()
            try:
                with conn:
                    with conn.cursor() as cur:
                        cur.execute(schema)
            finally:
                conn.close()
            break
        except psycopg2.OperationalError:
            if attempt == retries:
                raise
            time.sleep(delay)
    seed()


def seed() -> None:
    if query_one("SELECT COUNT(*) AS n FROM users")["n"] > 0:
        return

    users = [
        ("alice", "alice123", "user", "Alice Ben Salah"),
        ("bob", "bob123", "user", "Bob Trabelsi"),
        ("carol", "carol123", "agent", "Carol Mansour"),
        ("dave", "dave123", "admin", "Dave Gharbi"),
    ]
    for username, password, role, full_name in users:
        execute(
            "INSERT INTO users (username, password_hash, role, full_name) "
            "VALUES (%s, %s, %s, %s)",
            (username, hash_password(password), role, full_name),
        )

    ids = {
        row["username"]: row["id"]
        for row in query("SELECT id, username FROM users")
    }

    tickets = [
        (
            ids["alice"],
            "Cannot access VPN after password reset",
            "I reset my password this morning and now the VPN client rejects my "
            "credentials. I need access before the 14:00 customer call.",
            "open",
            "high",
        ),
        (
            ids["bob"],
            "Payroll portal shows the wrong salary",
            "My November payslip shows 3,200 TND instead of the agreed amount. "
            "Please check before the bank transfer runs.",
            "open",
            "normal",
        ),
        (
            ids["alice"],
            "Laptop replacement request",
            "The battery on my ThinkPad lasts about 40 minutes. Requesting a "
            "replacement under the hardware refresh policy.",
            "pending",
            "low",
        ),
        (
            ids["bob"],
            "Suspicious phishing email",
            "Received an email claiming to be from IT asking me to confirm my "
            "password on an external form. I did not click the link.",
            "closed",
            "normal",
        ),
    ]
    for owner_id, subject, body, status, priority in tickets:
        execute(
            "INSERT INTO tickets (owner_id, subject, body, status, priority) "
            "VALUES (%s, %s, %s, %s, %s)",
            (owner_id, subject, body, status, priority),
        )

    rows = query("SELECT id, subject FROM tickets ORDER BY id")
    by_subject = {row["subject"]: row["id"] for row in rows}

    comments = [
        (
            by_subject["Cannot access VPN after password reset"],
            ids["carol"],
            "MFA token reset. Temporary enrolment code: 4821-9931. Do not share.",
            True,
        ),
        (
            by_subject["Payroll portal shows the wrong salary"],
            ids["carol"],
            "HR case #4412. Confirmed salary is 4,850 TND gross; finance is "
            "correcting the November run.",
            True,
        ),
        (
            by_subject["Suspicious phishing email"],
            ids["bob"],
            "Forwarded the original message to the security team.",
            False,
        ),
    ]
    for ticket_id, author_id, body, internal in comments:
        execute(
            "INSERT INTO comments (ticket_id, author_id, body, internal) "
            "VALUES (%s, %s, %s, %s)",
            (ticket_id, author_id, body, internal),
        )
