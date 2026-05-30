from ...base.base_repository import BaseRepository
from ...dataclasses.user_data import UserCreation
from ..auth.user_manager import UserManager
from ..database.database_manager import db
from ..models.standard_user import StandardUser


class UserWriter(BaseRepository):
    def __init__(self, user: UserManager) -> None:
        self.user = user

    def change_password(self, new_password: str) -> None:
        if not self._fetch_row(StandardUser, filters={"id": self.user.user_id}):
            raise ValueError("User doesn't exists!")

    def reset_password(self, username: str) -> None:
        # TODO: reseting password with email?
        pass

    @classmethod
    def save_user(cls, data: UserCreation) -> None:
        if cls._fetch_row(StandardUser, filters={"master_username": data.username}):
            raise ValueError("User with that username already exists!")
        entry = StandardUser(
            master_username=data.username,
            master_password_hash=data.password,
            encryption_salt=data.salt,
        )
        with db.session() as session:
            session.add(entry)
            session.commit()
