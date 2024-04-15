from fastapi import APIRouter

# views_api.py is for you API endpoints that could be hit by another service

example_ext_api = APIRouter()


@example_ext_api.get("/api/v1/test/{test_data}")
async def api_example(test_data):
    # Do some python things and return the data
    return test_data
