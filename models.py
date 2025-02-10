from pydantic import BaseModel


class Example(BaseModel):
    id: str
    wallet: str


class CreateExample(BaseModel):
    wallet: str
