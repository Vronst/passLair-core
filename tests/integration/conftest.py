import pytest

from passlair.core.database.database_manager import db as original_db
from passlair.core.models.standard_user import StandardUser
from passlair.core.readers.user_reader import UserReader
from passlair.core.writers.user_writer import UserWriter


@pytest.fixture(autouse=True)
def set_up_db():
    original_db.init_sqlite(":memory:")
    return original_db


@pytest.fixture(autouse=False)
def register_user():
    """
    Registers a real user through the actual UserWriter pipeline (so the
    stored master_password/dek are consistent with what login/change_password
    will derive) before the test, and shreds it afterward.

    A hand-rolled StandardUser with made-up salt/dek bytes would never
    authenticate, since it bypasses derive_keys entirely.

    Yields:
        dict: username, email, plaintext password, and the new user's id.
    """
    username = "test_user"
    email = "example@example.com"
    password = "test_password"

    data, backup_phrase = UserWriter.prepare_new_user(username, email, password)
    UserWriter.save_user(data)
    user = UserReader.get_user_by_name(username)
    assert user is not None

    yield {
        "username": username,
        "email": email,
        "password": password,
        "user_id": user.id,
        "backup_phrase": backup_phrase,
    }

    with original_db.session() as session:
        _ = session.query(StandardUser).filter_by(username=username).delete()
