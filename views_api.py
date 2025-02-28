from http import HTTPStatus

import httpx
from fastapi import APIRouter, Depends, HTTPException
from lnbits.decorators import require_invoice_key

from .models import Example

example_ext_api = APIRouter()

# views_api.py is for you API endpoints that could be hit by another service


@example_ext_api.get("/api/v1/test/{example_data}", description="Example API endpoint")
async def api_example(example_data: str) -> Example:
    if example_data != "00000000":
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid example data",
        )
    # Do some python things and return the data
    return Example(id="2", wallet=example_data)


@example_ext_api.get(
    "/api/v1/vetted",
    description="Get the vetted extension readme",
    dependencies=[Depends(require_invoice_key)],
)
async def api_get_vetted():
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://raw.githubusercontent.com/lnbits/lnbits-extensions/main/README.md"
        )
        return resp.text
