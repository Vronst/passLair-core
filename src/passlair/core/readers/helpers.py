import logging

from ..auth.credentials import verify_password
from .user_reader import UserReader

logger = logging.getLogger(__name__)


def compare_passwords(user_id: str, password: str) -> bool:
    user = UserReader.get_user_by(id=user_id)
    if not user:
        logger.warning("compare_passwords: unknown user_id=%r", user_id)
        return False

    matched = verify_password(password, user.salt, user.master_password) is not None
    if not matched:
        logger.warning("compare_passwords: mismatch for user_id=%r", user_id)
    return matched
