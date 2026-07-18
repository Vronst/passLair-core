from ...base.base_repository import BaseRepository
from ..models.standard_user import StandardUser


class UserReader(BaseRepository):
    @classmethod
    def get_user_by_name(cls, username: str) -> None | StandardUser:
        return cls._fetch_row(StandardUser, filters={"username": username})

    @classmethod
    def get_user_by(cls, **kwargs) -> None | StandardUser:
        return cls._fetch_row(StandardUser, filters={**kwargs})
