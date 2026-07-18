from .base import Base


class PasswordCreation(Base):
    user_id: str
    service_name: str
    login: str
    password: str
    nonce: bytes
