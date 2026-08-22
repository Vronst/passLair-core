import json
from typing import override
import pyperclip

from passlair.base.abstract.base_importer import BaseImporter

class Importer(BaseImporter):

    @override
    def import_from_file(self, path: str, fmt: str) -> None:
        pass

    @override
    def import_from_clipboard(self, fmt: str) -> None:
        pass
