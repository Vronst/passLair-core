import logging

from ...base.base_repository import BaseRepository
from ..models.standard_user import StandardUser

logger = logging.getLogger(__name__)


class UserReader(BaseRepository):
    @classmethod
    def get_user_by_name(cls, username: str) -> None | StandardUser:
        logger.debug("Looking up user by username=%r", username)
        return cls._fetch_row(StandardUser, filters={"username": username})

    @classmethod
    def get_user_by(cls, **kwargs: object) -> None | StandardUser:
        logger.debug("Looking up user by %s", list(kwargs))
        return cls._fetch_row(StandardUser, filters={**kwargs})
