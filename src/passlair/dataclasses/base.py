from typing import cast

from pydantic import BaseModel


class Base(BaseModel):
    def __getitem__(self, attr: str) -> object:
        try:
            return cast(object, getattr(self, attr))
        except AttributeError:
            raise KeyError(attr)
