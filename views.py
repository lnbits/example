from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer

silnt_generic_router = APIRouter()


def silnt_renderer():
    return template_renderer(["siLNt/templates"])


@silnt_generic_router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(check_user_exists)):
    return silnt_renderer().TemplateResponse(
        "silnt/index.html", {"request": request, "user": user.json()}
    )
