import logging

from .base.abstract.authenticated_user import AuthenticatedUser
from .core.database import db
from .core.interface.identity import Identity
from .core.interface.password_manager import PasswordManager
from .dataclasses.facade_result import FacadeResult
from .dataclasses.import_result import ImportResult
from .share import Exporter, Importer, ImportFormatError

# Library convention: don't configure handlers here, just make sure logging
# calls never crash for consumers who haven't set up logging themselves.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "AuthenticatedUser",
    "Exporter",
    "FacadeResult",
    "Identity",
    "ImportFormatError",
    "ImportResult",
    "Importer",
    "PasswordManager",
    "db",
]
