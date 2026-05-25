from abc import ABC
from typing import Any, Type, TypeVar

from ..core.database.database_manager import db

T = TypeVar("T")


class BaseRepository(ABC):
    @classmethod
    def _fetch_row(cls, model: Type[T], *, filters: dict[str, Any]) -> T | None:
        with db.session() as session:
            return session.query(model).filter_by(**filters).first()
