import asyncio

from fastapi import APIRouter
from lnbits.db import Database
from lnbits.tasks import create_permanent_unique_task
from loguru import logger

from .tasks import wait_for_paid_invoices
from .views import example_ext_generic
from .views_api import example_ext_api

db = Database("ext_example")

scheduled_tasks: list[asyncio.Task] = []

example_ext: APIRouter = APIRouter(prefix="/example", tags=["example"])
example_ext.include_router(example_ext_generic)
example_ext.include_router(example_ext_api)

example_static_files = [
    {
        "path": "/example/static",
        "name": "example_static",
    }
]


def example_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)


def example_start():
    # ignore will be removed in lnbits `0.12.6`
    # https://github.com/lnbits/lnbits/pull/2417
    task = create_permanent_unique_task("ext_testing", wait_for_paid_invoices)  # type: ignore
    scheduled_tasks.append(task)
