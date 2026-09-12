from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


class SoftDeleteMixin:
    """Adds a nullable ``deleted_at`` tombstone. NULL means the row is live;
    a timestamp means it was soft-deleted. Every read path must filter
    ``deleted_at IS NULL`` -- a hard DELETE can't be replicated to the sync
    peer, a tombstone can."""

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=None, index=True
    )
