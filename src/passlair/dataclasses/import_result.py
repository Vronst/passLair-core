from typing import ClassVar

from pydantic import ConfigDict

from .base import Base


class ImportResult(Base):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
    imported: int
    skipped: int
