from collections.abc import Iterable
from itertools import chain
from typing import ClassVar, cast

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session, UOWTransaction

from ...base.abstract.base_facade import BaseFacade
from ...dataclasses.facade_result import FacadeResult
from ..database.database_manager import DatabaseManager, db
from ..models.base.base import Base
from ..models.standard_user import StandardUser
from ..models.vault_entry import VaultEntry


class SyncedDualDatabases(BaseFacade):
    """Allows for one local and one remote synced database.

    Creates/uses shared across library database, and
    connects to remote mariadb via provied params, syncing it
    to the local one. Allowing local storage with backup online.
    """

    vault_entry_fields: ClassVar[list[str]] = [
        "service_name",
        "login",
        "password",
        "nonce",
    ]
    standard_user_fields: ClassVar[list[str]] = [
        "username",
        "email",
        "master_password",
        "salt",
        "dek",
        "dek_nonce",
        "backup_dek",
        "backup_dek_nonce",
    ]
    supported_models: ClassVar[dict[str, type[Base]]] = {
        "vault_entry": VaultEntry,
        "standard_user": StandardUser,
    }

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
        full_url: str | None = None,
    ) -> None:
        if not full_url and not all([username, password, host, port, database]):
            raise ValueError("Params for mariadb incomplete.")

        self.sqlite: DatabaseManager = db
        self.sqlite.init_sqlite(sqlite_path)

        self.mariadb: DatabaseManager = DatabaseManager()
        self.mariadb.init_mariadb(
            full_url,
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
        )

        self.to_sync: dict[str, dict[str, str]] = {}

        event.listen(self.sqlite.session_factory, "after_flush", self._add_to_sync)
        event.listen(self.sqlite.session_factory, "after_commit", self._commit_sync)

    def sync_remote(self) -> FacadeResult:
        failed: list[tuple[str, dict[str, str]]] = []
        with self.mariadb.session() as session:
            for model_and_id, field_and_data in self.to_sync.items():
                model, model_id = model_and_id.split(":")
                entry = session.get(self.supported_models[model], model_id)
                if not entry:
                    failed.append((model_and_id, field_and_data))
                    continue

                field, data = next(iter(field_and_data.items()))
                setattr(entry, field, data)
                session.add(entry)

        if failed:
            return self._failure("Failed to sync some entries", {"failed": failed})

        return self._success("All entries were synched!")

    def _commit_sync(self, session: Session) -> None:
        pending = cast(
            "dict[str, dict[str, str]] | None", session.info.pop("pending_sync", None)
        )
        if not pending:
            return

        for model_and_id, field in pending.items():
            self.to_sync.setdefault(model_and_id, {}).update(field)

    def _add_to_sync(self, session: Session, _: UOWTransaction) -> None:
        storage = session.info
        storage.setdefault("pending_sync", {})
        pending = cast(dict[str, dict[str, str]], storage["pending_sync"])
        identities = chain(session.new, session.dirty)
        # Instance State
        for instance in cast(Iterable[object], identities):
            if not isinstance(instance, Base):
                continue

            fields, model = self._get_model_and_fields(instance)
            inspection = inspect(instance).attrs
            wraped_instance_id = inspection["id"].history.unchanged
            assert wraped_instance_id
            instance_id = cast(str, wraped_instance_id[0])
            for field in fields:
                _history = inspection[field].history
                if not _history.has_changes():
                    continue

                assert _history.added
                key = f"{model}:{instance_id}"
                pending.setdefault(key, {})[field] = _history.added[0]

    def _get_model_and_fields(self, instance: Base) -> tuple[list[str], str]:
        if isinstance(instance, VaultEntry):
            return self.vault_entry_fields, "vault_entry"

        elif isinstance(instance, StandardUser):
            return self.standard_user_fields, "standard_user"

        raise ValueError(f"Selected model {instance} is not supported.")
