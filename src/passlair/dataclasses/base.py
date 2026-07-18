from typing import Any

from pydantic import BaseModel


class Base(BaseModel):
    def __getitem__(self, attr) -> Any:
        try:
            return getattr(self, attr)
        except AttributeError:
            raise KeyError(attr)
