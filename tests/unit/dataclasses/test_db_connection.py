import pytest
from pydantic import ValidationError
from sqlalchemy import make_url

from passlair.dataclasses.db_connection import DBConnection


class TestPositive:
    def test_full_url_passes_through_untouched(self):
        """When full_url is supplied, the component check is skipped and the
        value is left exactly as given."""
        url = "mariadb+pymysql://u:p@localhost:3306/vault"
        conn = DBConnection(full_url=url)

        assert conn.full_url == url

    def test_components_build_expected_url(self):
        """All five components present -> a mariadb+pymysql URL is assembled."""
        conn = DBConnection(
            username="vronst",
            password="vault_password",
            host="127.0.0.1",
            port=3306,
            database="passlair_vault",
        )

        assert conn.full_url is not None
        assert make_url(conn.full_url) == make_url(
            "mariadb+pymysql://vronst:vault_password@127.0.0.1:3306/passlair_vault"
        )

    def test_special_characters_in_password_are_escaped(self):
        """URL.create must percent-encode reserved characters so the URL still
        parses back to the original password."""
        conn = DBConnection(
            username="vronst",
            password="p@ss/w:rd#",
            host="127.0.0.1",
            port=3306,
            database="passlair_vault",
        )

        assert conn.full_url is not None
        assert make_url(conn.full_url).password == "p@ss/w:rd#"


class TestNegative:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {},
            {"username": "vronst"},
            {
                "username": "vronst",
                "password": "x",
                "host": "127.0.0.1",
                "port": 3306,
            },  # database missing
        ],
    )
    def test_incomplete_components_raise(self, kwargs: dict[str, object]):
        """No full_url and at least one missing component -> ValidationError
        naming the missing field(s)."""
        with pytest.raises(ValidationError, match="Missing field/s"):
            _ = DBConnection(**kwargs)
