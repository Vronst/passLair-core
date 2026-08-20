import uuid

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import LargeBinary

from .base import Base


class StandardUser(Base):
    __tablename__: str = "standard_users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(
        String(150), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(150), unique=True, nullable=False, index=True
    )
    master_password: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Same DEK as above, but wrapped under a random backup KEK instead of the
    # password-derived one. The backup KEK itself is never stored - it's
    # shown to the user once so they can recover access if they forget
    # their password.
    backup_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    backup_dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
