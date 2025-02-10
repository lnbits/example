# crud.py is for communication with your extensions database

# add your dependencies here
# from .models import createExample, Example
from lnbits.db import Database

db = Database("ext_example")

# add your fnctions here

# async def create_a_record(data: Example) -> createExample:
#     example_id = urlsafe_short_hash()
#     example = Example(id=example_id, **data.dict())
#     await db.insert("example.example", example)
#     return example


# async def get_a_record(example_id: str) -> Optional[Example]:
#     return await db.fetchone(
#         "SELECT * FROM example.example WHERE id = :id", {"id": example_id}, Example
#     )
