from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import SECRET_KEY
from app.db import init_db, query
from app.metrics import render as render_metrics
from app.middleware import RequestContextMiddleware
from app.routes import admin, auth_routes, tickets

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="HelpDesk", lifespan=lifespan)

# SessionMiddleware signs the session cookie with the hardcoded SECRET_KEY.
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="helpdesk_session",
    same_site="lax",
    https_only=False,
)
app.add_middleware(RequestContextMiddleware)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(auth_routes.router)
app.include_router(tickets.router)
app.include_router(admin.router)


@app.get("/")
def index():
    return RedirectResponse("/tickets", status_code=303)


@app.get("/healthz")
def healthz():
    try:
        query("SELECT 1 AS ok")
        return {"status": "ok"}
    except Exception:
        return JSONResponse({"status": "error"}, status_code=503)


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    return render_metrics()
