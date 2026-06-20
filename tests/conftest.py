import pytest

from passlair.core.database.database_manager import DatabaseManager
from passlair.core.database.database_manager import db as original_db


@pytest.fixture(autouse=True)
def reset_database_singleton():
    """
    Crucial fixture! Since DatabaseManager is a Singleton, this clears the
    internal state before and after every single test to prevent leakages.
    """
    # Clear the global instance state
    original_db._engine = None
    original_db._session_factory = None
    yield
    original_db._engine = None
    original_db._session_factory = None


@pytest.fixture()
def db():
    original_db.init_sqlite(":memory:", force=True)
    return original_db
