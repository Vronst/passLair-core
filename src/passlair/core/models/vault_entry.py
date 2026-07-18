import uuid

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class VaultEntry(Base):
    """
    Represents an individual encrypted credential stored in the user's vault.

    This model persists the encrypted payload and the unique initialization vector
    (nonce) required for decryption. It serves as the primary data structure for
    the 'Read Path' (UserReader) and 'Write Path' (PasswordWriter) operations.

    Attributes:
        id (str): The unique primary key for the entry, stored as a UUID4 string.
        user_id (str): Foreign identifier linking the entry to a specific user.
            Indexed for high-performance lookup during vault retrieval.
        service_name (str): The name or URL of the service (e.g., 'github.com').
            Used as a search filter in the VaultReader.
        login (str): Optional username or email associated with the service.
        password (str): The AES-GCM encrypted ciphertext of the
            raw password. Must be decrypted using the user's active session key.
        nonce (str): A unique initialization vector (IV) used during
            the encryption of this specific entry. Never reused across entries.
    """

    __tablename__ = "vault_entries"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    service_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    login: Mapped[str] = mapped_column(String(255), nullable=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
