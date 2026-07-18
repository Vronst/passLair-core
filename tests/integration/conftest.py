import pytest

from passlair.core.database.database_manager import db as original_db
from passlair.core.models.standard_user import StandardUser


@pytest.fixture(autouse=True)
def set_up_db():
    original_db.init_sqlite(":memory:")
    return original_db


@pytest.fixture(autouse=False)
def register_user():
    """
    Sets up a clean test user before the test,
    provides it to the test function, and shreds it afterward.

    Yields:
        dict
    """
    data = {
        "username": "test_user",
        "master_password": "password",
        "email": "example@example.com",
        "salt": "salt",
    }
    user = StandardUser(**data)
    data["user_id"] = user.id

    with original_db.session() as session:
        session.add(user)
        session.commit()

    yield data

    with original_db.session() as session:
        session.query(StandardUser).filter_by(username="test_user").delete()
