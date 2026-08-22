import logging
import json
from typing import override
import pyperclip

from passlair.base.abstract.base_importer import BaseImporter

logger = logging.getLogger(__name__)


class Importer(BaseImporter):

    @override
    def import_from_file(self, path: str, fmt: str) -> None:
        match fmt:
            case 'txt':
                logger.info("Imporing from txt file.")
                self.import_from_txt(path)
            case 'json':
                logger.info("Imporing from json file.")
                self.import_from_json(path)
            case 'csv':
                logger.info("Importing from csv file.")
                self.import_from_csv(path)
            case _:
                logger.error("Invalid clipboard format.")
                raise ValueError("Invalid format. Choose txt/json/csv")

    def _save_json(self, data: dict[str, dict[str, str]]) -> None:
        pass

    def import_from_json(self, path: str) -> None:
        pass

    def import_from_txt(self, path: str) -> None:
        pass

    def import_from_csv(self, path: str) -> None:
        pass

    def import_txt_from_clipboard(self) -> None:
        clip = pyperclip.paste()

    def import_json_from_clipboard(self) -> None:
        clip = pyperclip.paste()

    @override
    def import_from_clipboard(self, fmt: str) -> None:
        match fmt:
            case 'txt':
                logger.info("Imporing txt from clipboard.")
                self.import_txt_from_clipboard()
            case 'json':
                logger.info("Imporing json from clipboard.")
                self.import_json_from_clipboard()
            case _:
                logger.error("Invalid clipboard format.")
                raise ValueError("Invalid format. Choose txt/json")
