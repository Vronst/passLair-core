from pydantic import ConfigDict

from .base import Base


class FacadeResult(Base):
    model_config = ConfigDict(frozen=True)
    success: bool
    messege: str
    data: dict
