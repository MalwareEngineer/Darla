"""Kit model — represents a downloaded phishing kit archive."""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from darla.models.actor import Actor
    from darla.models.analysis_result import AnalysisResult
    from darla.models.campaign import Campaign
    from darla.models.family import Family
    from darla.models.indicator import Indicator
    from darla.models.investigation import Investigation
    from darla.models.stage import Stage


class KitStatus(enum.StrEnum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    FAILED = "failed"


class Kit(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "kits"

    # Source information
    source_url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_feed: Mapped[str | None] = mapped_column(String(50))
    # File metadata
    filename: Mapped[str | None] = mapped_column(String(512))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    mime_type: Mapped[str | None] = mapped_column(String(128))

    # Hashes — index but NOT unique.  Two kits in different
    # investigations can legitimately share a SHA256 when the attacker's
    # AITM/relay infrastructure serves identical bytes to multiple
    # campaigns.  We treat that as a CORRELATION signal (set
    # ``duplicate_of_kit_id``) rather than a redundancy to drop.  The
    # UNIQUE constraint was getting in the way of letting both kits
    # carry their own analysis output (IOCs, YARA matches, similarity
    # edges) while still being linked back to their canonical sibling.
    # See migration ``w3s9t0u1v2n4`` for the index rebuild.
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    tlsh: Mapped[str | None] = mapped_column(String(72), index=True)

    # Processing state
    status: Mapped[KitStatus] = mapped_column(
        Enum(KitStatus), default=KitStatus.PENDING, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text)

    # Pattern versioning — NULL means pre-versioning (stale)
    pattern_version: Mapped[int | None] = mapped_column(Integer, index=True)

    # Chain/investigation tracking
    parent_kit_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("kits.id", ondelete="CASCADE"), index=True
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="SET NULL"), index=True
    )
    chain_depth: Mapped[int] = mapped_column(Integer, default=0)
    discovery_method: Mapped[str | None] = mapped_column(String(50))

    # Dedup tracking — points to the kit this one is a duplicate of
    duplicate_of_kit_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("kits.id", ondelete="SET NULL"), index=True
    )

    # Storage
    local_path: Mapped[str | None] = mapped_column(Text)

    # Post-download analysis chain progress.  Set to the **name of the
    # step that started but may not yet have completed** by a Celery
    # task_prerun signal (see ``darla.tasks.analysis._record_chain_cursor``).
    # Used by the ``recover_chain_cursors`` recovery beat job to resume
    # stalled chains without restarting from ``download_kit`` (which
    # would waste the existing local_path content + re-trigger
    # browser-render fanout).  ``None`` for kits that haven't entered
    # post-download chain yet, or that completed cleanly.
    chain_cursor: Mapped[str | None] = mapped_column(String(64))

    # Relationships
    parent_kit: Mapped[Kit | None] = relationship(
        "Kit", remote_side="Kit.id", back_populates="child_kits",
        foreign_keys=[parent_kit_id],
    )
    child_kits: Mapped[list[Kit]] = relationship(
        "Kit", back_populates="parent_kit",
        foreign_keys=[parent_kit_id],
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    investigation: Mapped[Investigation | None] = relationship(
        back_populates="kits", foreign_keys=[investigation_id]
    )
    indicators: Mapped[list[Indicator]] = relationship(
        back_populates="kit", cascade="all, delete-orphan", passive_deletes=True
    )
    analysis_results: Mapped[list[AnalysisResult]] = relationship(
        back_populates="kit", cascade="all, delete-orphan", passive_deletes=True
    )
    campaigns: Mapped[list[Campaign]] = relationship(
        secondary="campaign_kits", back_populates="kits"
    )
    families: Mapped[list[Family]] = relationship(
        secondary="family_kits", back_populates="kits"
    )
    actors: Mapped[list[Actor]] = relationship(
        secondary="kit_actors", back_populates="kits"
    )
    stages: Mapped[list[Stage]] = relationship(
        back_populates="kit",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Stage.seq",
    )

    __table_args__ = (
        Index("ix_kits_tlsh_status", "tlsh", "status"),
        Index("ix_kits_created_at", "created_at"),
    )
