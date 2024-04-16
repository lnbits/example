from fastapi import APIRouter

from .models import Example

# views_api.py is for you API endpoints that could be hit by another service

example_ext_api = APIRouter(
    prefix="/api/v1",
    tags=["example"],
)


@example_ext_api.get("/{example_data}", description="Example API endpoint")
async def api_example(example_data: str) -> Example:
    # Do some python things and return the data
    return Example(id="1", wallet=example_data)
