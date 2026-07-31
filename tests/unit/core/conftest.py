from unittest.mock import MagicMock, patch

import pytest

from passlair.core.auth.user_manager import UserManager
from passlair.core.models.standard_user import StandardUser
from passlair.dataclasses.user_data import UserCreation


@pytest.fixture
def mock_db_session():
    """Fixture to cleanly abstract the context-managed DB session nesting."""
    with patch("passlair.core.writers.user_writer.db") as mock_db:
        mock_session = MagicMock()
        # Chaining the context manager __enter__ state cleanly
        mock_db.session.return_value.__enter__.return_value = mock_session
        # Without this, MagicMock's auto __exit__ returns truthy and silently
        # swallows exceptions raised inside "with db.session() as session:".
        mock_db.session.return_value.__exit__.return_value = False
        yield mock_session, mock_db


@pytest.fixture
def mock_user_data():
    """Generates standard user data for validation tests."""
    return UserCreation(
        username="test_user",
        email="test@example.com",
        master_password=b"secure_password_hash",
        salt=b"random_salt",
        dek=b"encrypted_dek",
        dek_nonce=b"dek_nonce_12",
    )


@pytest.fixture
def mock_user():
    """Generates StandarUser mock for tests."""
    mock = MagicMock(spec=StandardUser)
    mock.id = "secret_id"
    # passlair_crypto's derive_keys is currently a stub returning a constant
    # hash (vec![1u8; 32]); this must match it for "correct password" tests
    # to be meaningful until real crypto lands.
    mock.master_password = bytes([1] * 32)
    mock.salt = b"salt"
    mock.dek = b"dek"
    mock.dek_nonce = b"dek_nonce_12"
    return mock


@pytest.fixture
def mock_user_manager():
    """Mocks user-manager for unit testing."""
    mock = MagicMock(spec=UserManager)
    mock.get_session_key.return_value = "session_key"
    mock.user_id = "string_id"

    return mock
