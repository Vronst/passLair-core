import pytest

from passlair.core.database.database_manager import db as original_db


@pytest.fixture(autouse=True)
def reset_database_state():
    """
    Crucial fixture! The module-global ``db`` instance is shared across every
    test, so its engine/session state is cleared before and after each test to
    prevent leakage between them.
    """
    original_db.dispose()
    yield
    original_db.dispose()


@pytest.fixture()
def db():
    return original_db
