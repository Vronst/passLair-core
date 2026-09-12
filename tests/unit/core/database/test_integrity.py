import pytest
from sqlalchemy.exc import IntegrityError

from passlair.core.database.integrity import is_unique_violation, violation_names


def _integrity_error(orig: Exception) -> IntegrityError:
    return IntegrityError("INSERT", {}, orig)


class TestIsUniqueViolation:
    @pytest.mark.parametrize(
        "orig",
        [
            Exception("UNIQUE constraint failed: standard_users.username"),
            Exception("UNIQUE constraint failed: standard_users.email"),
            Exception(1062, "Duplicate entry 'bob' for key 'standard_users.username'"),
            Exception(1062, "Duplicate entry '...' for key 'PRIMARY'"),
        ],
    )
    def test_true_for_uniqueness_violations(self, orig: Exception):
        assert is_unique_violation(_integrity_error(orig)) is True

    @pytest.mark.parametrize(
        "orig",
        [
            Exception("NOT NULL constraint failed: standard_users.email"),
            Exception("FOREIGN KEY constraint failed"),
            Exception(1048, "Column 'email' cannot be null"),
        ],
    )
    def test_false_for_other_integrity_errors(self, orig: Exception):
        assert is_unique_violation(_integrity_error(orig)) is False


class TestViolationNames:
    def test_returns_first_matching_candidate(self):
        err = _integrity_error(
            Exception("UNIQUE constraint failed: standard_users.email")
        )
        assert violation_names(err, "username", "email") == "email"

    def test_candidate_order_wins_on_multiple_matches(self):
        err = _integrity_error(
            Exception("Duplicate entry for key 'users.username_email'")
        )
        assert violation_names(err, "username", "email") == "username"

    def test_none_when_no_candidate_named(self):
        err = _integrity_error(Exception("Duplicate entry '...' for key 'PRIMARY'"))
        assert violation_names(err, "username", "email") is None

    def test_match_is_case_insensitive(self):
        err = _integrity_error(Exception("Duplicate entry for key 'USERS.USERNAME'"))
        assert violation_names(err, "username") == "username"
