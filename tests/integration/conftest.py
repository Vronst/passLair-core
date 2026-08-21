import pytest
from collections.abc import Generator

from passlair.core.database.database_manager import db as original_db
from passlair.core.models.standard_user import StandardUser
from passlair.core.readers.user_reader import UserReader
from passlair.core.writers.user_writer import UserWriter
from passlair.core.writers.password_writer import PasswordWriter
from passlair.core.auth.user_manager import UserManager


@pytest.fixture(autouse=True)
def set_up_db():
    original_db.init_sqlite(":memory:")
    return original_db

def _register_user(username: str, email: str, password: str = 'test_password'):
    """
    Registers a real user through the actual UserWriter pipeline (so the
    stored master_password/dek are consistent with what login/change_password
    will derive) before the test, and shreds it afterward.

    A hand-rolled StandardUser with made-up salt/dek bytes would never
    authenticate, since it bypasses derive_keys entirely.

    Yields:
        dict: username, email, plaintext password, and the new user's id.
    """
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

@pytest.fixture(autouse=False)
def register_user() -> Generator[dict[str, str], None, None]:
    username = "test_user"
    email = "example@example.com"
    password = "test_password"
    yield from _register_user(username, email, password)


@pytest.fixture(autouse=False)
def register_user2() -> Generator[dict[str, str], None, None]:
    username = "test_user2"
    email = "example2@example.com"
    password = "test_password2"
    yield from _register_user(username, email, password)


@pytest.fixture(autouse=False)
def user_manager_with_passwords(
    register_user: dict[str, str]
) -> tuple[UserManager, list[dict[str, str]]]:
    passwords = [
        {
            'service': 'service1',
            'login': 'login1',
            'password': 'password1',
        },
        {
            'service': 'service2',
            'login': 'login2',
            'password': 'password2',
        },
        {
            'service': 'service3',
            'login': 'login3',
            'password': 'password3',
        }
    ]
    username = register_user['username']
    password = register_user['password']
    manager = UserManager()
    assert manager.login(username, password)

    pass_writer = PasswordWriter(manager)
    for credentials in passwords:
        assert pass_writer.save_password(**credentials)

    return manager, passwords
