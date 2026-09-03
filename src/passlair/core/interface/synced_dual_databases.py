from ...dataclasses.facade_result import FacadeResult
from ...base.abstract.base_facade import BaseFacade
from ..database.database_manager import DatabaseManager


class SyncedDualDatabases(BaseFacade):
    def __init__(
        self,
        sqlite_path: str,
        /,
        *,
        username: str | None = None,
        password: str | None = None,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        full_url: str | None = None
    ) -> None:
        if not full_url and all([username, password, host, port, database]):
            raise ValueError("Params for mariadb incomplete.")

        self.sqlite: DatabaseManager = DatabaseManager()
        self.sqlite.init_sqlite(sqlite_path)

        self.mariadb: DatabaseManager = DatabaseManager()
        self.mariadb.init_mariadb(
            full_url,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database
        )

    def sync_remote(self) -> FacadeResult:
        pass
