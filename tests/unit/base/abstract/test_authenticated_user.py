from typing import override
import pytest

from passlair.base.abstract.authenticated_user import AuthenticatedUser


class FakeAuthenticatedUser(AuthenticatedUser):
    @override
    def get_session_key(self) -> bytes:
        return b"session_key"

    @property
    @override
    def user_id(self):
        return "some_id"


class TestPositive:
    def test_require_returns_a_valid_authenticated_user(self):
        user = FakeAuthenticatedUser()

        assert AuthenticatedUser.require(user) is user


class TestNegative:
    def test_require_rejects_none(self):
        with pytest.raises(TypeError):
            _ = AuthenticatedUser.require(None)

    def test_require_rejects_an_unrelated_object(self):
        with pytest.raises(TypeError):
            _ = AuthenticatedUser.require(object())
