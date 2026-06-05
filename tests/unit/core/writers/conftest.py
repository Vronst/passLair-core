from unittest.mock import MagicMock, patch

import pytest

from passlair.core.auth.user_manager import UserManager
from passlair.dataclasses.user_data import UserCreation


@pytest.fixture
def mock_db_session():
    """Fixture to cleanly abstract the context-managed DB session nesting."""
    with patch("passlair.core.writers.user_writer.db") as mock_db:
        mock_session = MagicMock()
        # Chaining the context manager __enter__ state cleanly
        mock_db.session.return_value.__enter__.return_value = mock_session
        yield mock_session, mock_db


@pytest.fixture
def mock_user_data():
    """Generates standard user data for validation tests."""
    return UserCreation(
        username="test_user", password="secure_password", salt=b"random_salt_bytes"
    )


@pytest.fixture
def mock_user_manager():
    """Mocks user-manager for unit testing."""
    mock = MagicMock(spec=UserManager)
    mock.get_session_key.return_value = "session_key"
    mock.user_id = "string_id"

    return mock
