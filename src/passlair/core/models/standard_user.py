import uuid

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class StandardUser(Base):
    __tablename__ = "standard_users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    master_username: Mapped[str] = mapped_column(
        String(150), unique=True, nullable=False, index=True
    )

    # Store the Argon2id/PBKDF2 hash of the master password strictly for vault authentication
    master_password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    encryption_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
