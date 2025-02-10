import asyncio

from fastapi import APIRouter
from loguru import logger

from .crud import db
from .tasks import wait_for_paid_invoices
from .views import example_ext_generic
from .views_api import example_ext_api

example_ext: APIRouter = APIRouter(prefix="/example", tags=["example"])
example_ext.include_router(example_ext_generic)
example_ext.include_router(example_ext_api)

example_static_files = [
    {
        "path": "/example/static",
        "name": "example_static",
    }
]

scheduled_tasks: list[asyncio.Task] = []


def example_stop():
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)


def example_start():
    from lnbits.tasks import create_permanent_unique_task

    task = create_permanent_unique_task("ext_testing", wait_for_paid_invoices)
    scheduled_tasks.append(task)


__all__ = [
    "db",
    "example_ext",
    "example_static_files",
    "example_start",
    "example_stop",
]
