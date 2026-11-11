"""Jinja2 environment and a small render helper."""

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.auth import get_current_user

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def render(request, name: str, status_code: int = 200, **context):
    context.setdefault("user", get_current_user(request))
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=context,
        status_code=status_code,
    )
