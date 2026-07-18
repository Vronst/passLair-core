from .base import Base


class UserCreation(Base):
    """
    Args:
        username (str)
        email (str)
        password (str)
        salt (str)
    """
    username: str
    email: str
    master_password: str
    salt: str
