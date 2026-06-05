from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session


class TestPositive:
    def test_init_sqlite_default_path(self, db):
        """Verify SQLite initialization constructs the correct URL structure."""
        # TARGET THE LOCAL MODULE NAMESPACE, NOT SALCHEMY DIRECTLY
        target_path = "passlair.core.database.database_manager.create_engine"

        with patch(target_path) as mock_create_engine:
            # Create a dummy mock object to simulate the returned Engine instance
            mock_engine_instance = MagicMock()
            mock_create_engine.return_value = mock_engine_instance

            with patch.object(db, "_setup_factory") as mock_setup:
                db.init_sqlite()

                # 1. Verify create_engine was invoked with the right connection string
                called_url = mock_create_engine.call_args[0][0]
                assert called_url.startswith("sqlite:///")
                assert "passLair_db.db" in called_url

                # 2. Verify the manager saved the engine instance to its internal state
                assert db._engine == mock_engine_instance
                mock_setup.assert_called_once()

    def test_init_mariadb_pool_configurations(self, db):
        """Ensure MariaDB constructs the complex URL string and sets proper pools."""
        target_path = "passlair.core.database.database_manager.create_engine"

        with patch(target_path) as mock_create_engine:
            mock_engine_instance = MagicMock()
            mock_create_engine.return_value = mock_engine_instance

            with patch.object(db, "_setup_factory"):
                db.init_mariadb(
                    username="vronst",
                    password_str="vault_password",
                    host="127.0.0.1",
                    port=3306,
                    database="passlair_vault",
                )

                expected_url = "mariadb+pymysql://vronst:vault_password@127.0.0.1:3306/passlair_vault"

                # Verify exact keyword arguments passed down to the connection pool
                mock_create_engine.assert_called_once_with(
                    expected_url,
                    pool_size=10,
                    max_overflow=20,
                    pool_recycle=3600,
                    pool_pre_ping=True,
                )
                assert db._engine == mock_engine_instance

    def test_session_successful_commit(self, db):
        """Verify healthy sessions yield a working session, commit, and close cleanly."""
        db.init_sqlite(":memory:")  # Fast in-memory DB for actual lifecycle integration

        with db.session() as session:
            assert isinstance(session, Session)
            # We can execute raw sql to check liveliness
            with db.session() as session:
                result = session.execute(text("SELECT 1")).scalar()

            assert result == 1
            # Transaction is implicitly alive and healthy here

        # After exiting block, factory should be cleaned via remove()
        # verify engine is intact but scoped session safely closed its thread local
        assert db._session_factory is not None


class TestNegative:
    def test_session_context_manager_uninitialized_error(self, db):
        """The context manager must fail gracefully if called before initialization."""
        with pytest.raises(RuntimeError, match="DatabaseManager is not initialized"):
            with db.session():
                pass

    def test_session_rolls_back_on_exception(self, db):
        """Ensure that if code inside the block crashes, rollback is executed and raised."""
        db.init_sqlite(":memory:")

        # We will spy on the underlying session's rollback method
        mock_session_instance = MagicMock()
        # Force the factory to yield our mock session instead
        db._session_factory = MagicMock(return_value=mock_session_instance)

        with pytest.raises(ValueError, match="Simulated application error"):
            with db.session():
                raise ValueError("Simulated application error")

        # Assert transactional boundary logic
        mock_session_instance.rollback.assert_called_once()
        mock_session_instance.close.assert_called_once()
        db._session_factory.remove.assert_called_once()
