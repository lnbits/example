from fastapi import APIRouter, Depends, Request
from lnbits.core.models import User
from lnbits.decorators import check_user_exists
from lnbits.helpers import template_renderer
from starlette.responses import HTMLResponse

example_ext_generic = APIRouter()


@example_ext_generic.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    user: User = Depends(check_user_exists),
):
    return template_renderer(["example/templates"]).TemplateResponse(
        "example/index.html", {"request": request, "user": user.dict()}
    )
