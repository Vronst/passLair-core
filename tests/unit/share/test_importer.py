import pytest
from pytest_mock import MockerFixture

from passlair.share.importer import Importer


class TestPositive:
    @pytest.mark.parametrize(
        "fmt, target",
        [
            ("txt", "import_from_txt"),
            ("json", "import_from_json"),
            ("csv", "import_from_csv"),
        ],
    )
    def test_import_from_file_dispatches_by_format(
        self, mocker: MockerFixture, fmt: str, target: str
    ) -> None:
        importer = Importer()
        mocked = mocker.patch.object(importer, target)

        importer.import_from_file("some/path", fmt)

        mocked.assert_called_once_with("some/path")

    @pytest.mark.parametrize(
        "fmt, target",
        [
            ("txt", "import_txt_from_clipboard"),
            ("json", "import_json_from_clipboard"),
        ],
    )
    def test_import_from_clipboard_dispatches_by_format(
        self, mocker: MockerFixture, fmt: str, target: str
    ) -> None:
        importer = Importer()
        mocked = mocker.patch.object(importer, target)

        importer.import_from_clipboard(fmt)

        mocked.assert_called_once_with()

    def test_import_from_file_dispatches_only_to_matching_format(
        self, mocker: MockerFixture
    ) -> None:
        importer = Importer()
        txt = mocker.patch.object(importer, "import_from_txt")
        json_ = mocker.patch.object(importer, "import_from_json")
        csv_ = mocker.patch.object(importer, "import_from_csv")

        importer.import_from_file("some/path", "json")

        json_.assert_called_once_with("some/path")
        txt.assert_not_called()
        csv_.assert_not_called()


class TestNegative:
    def test_import_from_file_rejects_unknown_format(
        self, mocker: MockerFixture
    ) -> None:
        importer = Importer()
        txt = mocker.patch.object(importer, "import_from_txt")
        json_ = mocker.patch.object(importer, "import_from_json")
        csv_ = mocker.patch.object(importer, "import_from_csv")

        with pytest.raises(ValueError):
            importer.import_from_file("some/path", "xml")

        txt.assert_not_called()
        json_.assert_not_called()
        csv_.assert_not_called()

    def test_import_from_clipboard_rejects_unknown_format(
        self, mocker: MockerFixture
    ) -> None:
        importer = Importer()
        txt = mocker.patch.object(importer, "import_txt_from_clipboard")
        json_ = mocker.patch.object(importer, "import_json_from_clipboard")

        with pytest.raises(ValueError):
            importer.import_from_clipboard("csv")

        txt.assert_not_called()
        json_.assert_not_called()
