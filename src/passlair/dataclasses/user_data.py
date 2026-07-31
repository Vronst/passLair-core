from .base import Base


class UserCreation(Base):
    """
    Args:
        username (str)
        email (str)
        master_password (bytes): Password hash produced by derive_keys.
        salt (bytes)
        dek (bytes): DEK encrypted under the KEK derived from the password.
        dek_nonce (bytes)
    """
    username: str
    email: str
    master_password: bytes
    salt: bytes
    dek: bytes
    dek_nonce: bytes
