import pytest
from fastapi import APIRouter

from example import example_ext, example_start, example_stop


# just import router and add it to a test router
@pytest.mark.asyncio
async def test_router():
    router = APIRouter()
    router.include_router(example_ext)
    assert 1 == 1

@pytest.mark.asyncio
async def test_start_and_stop():
    example_start()
    example_stop()
