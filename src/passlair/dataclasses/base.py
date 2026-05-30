from typing import Any

from pydantic import BaseModel


class Base(BaseModel):
    def __getitem__(self, attr) -> Any:
        return getattr(self, attr)
