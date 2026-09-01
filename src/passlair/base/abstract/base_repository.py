import logging
from abc import ABC
from typing import TypeVar

from ...core.database.database_manager import db
from ...core.models.base import SoftDeleteMixin

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=SoftDeleteMixin)


class BaseRepository(ABC):
    @classmethod
    def _fetch_row(cls, model: type[T], *, filters: dict[str, object]) -> T | None:
        # Log filter keys only -- values may include user_id/service names,
        # but could just as easily be extended with sensitive lookups later.
        logger.debug("Fetching %s filtered by %s", model.__name__, list(filters))
        with db.session() as session:
            row = (
                session.query(model)
                .filter_by(**filters)
                .filter(model.deleted_at.is_(None))
                .first()
            )

        logger.debug(
            "%s lookup %s", model.__name__, "found a row" if row else "found nothing"
        )
        return row
