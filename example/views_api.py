from http import HTTPStatus

import httpx
from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from lnbits.decorators import WalletTypeInfo, get_key_type

from .models import Example

# views_api.py is for you API endpoints that could be hit by another service

example_ext_api = APIRouter(
    prefix="/api/v1",
    tags=["example"],
)


@example_ext_api.get("/test/{example_data}", description="Example API endpoint")
async def api_example(example_data: str) -> Example:
    # Do some python things and return the data
    return Example(id="1", wallet=example_data)


@example_ext_api.get("/vetted", description="Get the vetted extension readme")
async def api_get_vetted(wallet: WalletTypeInfo = Depends(get_key_type)):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://raw.githubusercontent.com/lnbits/lnbits-extensions/main/README.md"
            )
            return resp.text
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
