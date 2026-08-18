import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from ...base import SingletonMeta
from ..models.base import Base

logger = logging.getLogger(__name__)


class DatabaseManager(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self._engine = None
        self._session_factory = None

    def _reinit_check(self, force: bool = False) -> bool:
        if self._engine:
            if not force:
                return False

            if self._session_factory:
                self._session_factory.remove()

            self._engine.dispose()
        return True

    def init_sqlite(self, filepath: str | None = None, *, force: bool = False) -> None:
        """Initializes a local SQLite database configuration."""
        if not self._reinit_check(force):
            logger.debug("SQLite already initialized, skipping re-init (force=False).")
            return

        filepath = filepath or str(Path(__file__).parents[4] / "passLair_db.db")
        database_url = f"sqlite:///{filepath}"
        logger.info("Initializing SQLite database at %s", filepath)

        self._engine = create_engine(
            database_url, connect_args={"check_same_thread": False}
        )
        self._setup_factory()
        self.create_tables(Base.metadata)

    def init_mariadb(
        self,
        username: str,
        password_str: str,
        host: str,
        port: int,
        database: str,
        *,
        force: bool = False,
    ) -> None:
        """Initializes a networked MariaDB database configuration using the pymysql driver."""
        # URL Format: mariadb+pymysql://user:pass@host:port/dbname
        database_url = (
            f"mariadb+pymysql://{username}:{password_str}@{host}:{port}/{database}"
        )
        if not self._reinit_check(force):
            logger.debug("MariaDB already initialized, skipping re-init (force=False).")
            return

        # Never log database_url directly -- it embeds password_str in cleartext.
        logger.info(
            "Initializing MariaDB connection to %s:%s/%s as %s",
            host,
            port,
            database,
            username,
        )

        self._engine = create_engine(
            database_url,
            pool_size=10,  # Keeps up to 10 connections open
            max_overflow=20,  # Can spawn 20 extra if traffic spikes
            pool_recycle=3600,  # Recycles connections every hour to prevent timeouts
            pool_pre_ping=True,  # Checks if connection is alive before issuing queries
        )
        self._setup_factory()
        self.create_tables(Base.metadata)

    def _setup_factory(self) -> None:
        """Internal helper to tie the engine to the session factories."""
        local_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self._engine,
            expire_on_commit=False,
        )
        # scoped_session ensures thread-safety across your library
        self._session_factory = scoped_session(local_factory)

    def create_tables(self, base_metadata: MetaData) -> None:
        """Utility to generate the database schema tables if they don't exist yet."""
        if self._engine is None:
            raise RuntimeError(
                "DatabaseManager must be initialized before creating tables."
            )
        base_metadata.create_all(bind=self._engine)

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        Context manager providing a secure scope for database operations.
        Automatically commits changes or rolls back transactions on failure.
        """
        if self._session_factory is None:
            raise RuntimeError(
                "DatabaseManager is not initialized. Call init_sqlite or init_mariadb first."
            )

        db_session: Session = self._session_factory()
        try:
            yield db_session
            db_session.commit()
        except Exception:
            logger.exception("Session raised, rolling back transaction.")
            db_session.rollback()
            raise
        finally:
            db_session.close()
            self._session_factory.remove()


# --- Instantiation for Library Use ---
# Create a single global instance that modules in your library can import
db = DatabaseManager()
