from fastapi import APIRouter

from .models import Example

# views_api.py is for you API endpoints that could be hit by another service

example_ext_api = APIRouter()


@example_ext_api.get("/api/v1/test/{test_data}")
async def api_example(test_data: str) -> Example:
    # Do some python things and return the data
    return Example(id="1", wallet=test_data)
