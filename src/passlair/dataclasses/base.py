from pydantic import BaseModel


class Base(BaseModel):
    def __getitem__(self, attr: str) -> object:
        try:
            return getattr(self, attr)
        except AttributeError:
            raise KeyError(attr)
