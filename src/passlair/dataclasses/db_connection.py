from typing import Self
from pydantic import model_validator
from sqlalchemy import URL

from .base import Base


class DBConnection(Base):
    username: str | None = None
    password: str | None = None
    host: str | None = None
    port: int | None = None
    database: str | None = None
    full_url: str | None = None

    @model_validator(mode="after")
    def _check_conditional_requirements(self) -> Self:
        if self.full_url:
            return self

        fields = ["username", "password", "host", "port", "database"]
        missing = [name for name in fields if getattr(self, name) is None]

        if missing:
            raise ValueError(f"Missing field/s: {missing}")

        # render_as_string(hide_password=False) so the built URL keeps the
        # password; URL.create handles escaping of special characters.
        self.full_url = URL.create(
            "mariadb+pymysql",
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            database=self.database,
        ).render_as_string(hide_password=False)

        return self
