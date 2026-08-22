from collections.abc import Mapping
from typing import ClassVar

from pydantic import ConfigDict

from .base import Base


class FacadeResult(Base):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    success: bool
    messege: str
    data: Mapping[str, object]
