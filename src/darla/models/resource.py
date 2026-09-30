"""Resource model — content-addressed sub-resources loaded by a stage.

A remotely-fetched (or inline) script, stylesheet, XHR/fetch response,
iframe document or WebSocket transcript is a *property of the stage whose
page loaded it*, not a node in the attack-flow tree.  The one exception —
a script that causes navigation — is already handled upstream by the
chain crawler's ``svg_chain_terminal`` path, which promotes the terminal
URL to its own kit.

Storage is content-addressed: the same jQuery build, obfuscator stub or
bot-check library shared across many stages and investigations collapses
to a single :class:`Resource` row keyed by SHA-256.  A stage links to it
through :class:`StageResource`, which records the per-load context (the
URL it was fetched from, what initiated the load, and which document in
the render it belonged to).

For obfuscated kits the interesting bytes are usually in an *inline*
``<script>`` block, so those are extracted and hashed as resources too
(``initiator="inline"``).  Scripts are additionally fingerprinted after
deobfuscation (``tlsh`` here is over the raw bytes; the deobfuscated TLSH
lives in ``meta``), because obfuscator output rotates per victim and
would otherwise defeat SHA-256 matching.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    BigInteger,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from darla.models.stage import Stage

# JSONB in production (Postgres); portable JSON under SQLite test harnesses.
_JSON = JSONB().with_variant(JSON(), "sqlite")


class Resource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A unique piece of sub-resource content, keyed by SHA-256."""

    __tablename__ = "resources"

    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tlsh: Mapped[str | None] = mapped_column(String(72), index=True)
    size: Mapped[int | None] = mapped_column(BigInteger)
    content_type: Mapped[str | None] = mapped_column(String(128))
    # Relative path (under the owning render's download dir) to the first
    # on-disk copy of these bytes.  Content is identical across every
    # stage_resource that references this row, so one copy suffices.
    path: Mapped[str | None] = mapped_column(Text)
    # Extra fingerprints / flags: deobfuscated tlsh, is_inline, minified,
    # detected library name, endpoint list pulled from the body, etc.
    meta: Mapped[dict] = mapped_column(_JSON, default=dict)

    stage_resources: Mapped[list[StageResource]] = relationship(
        back_populates="resource",
        passive_deletes=True,
    )


class StageResource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Junction: a stage loaded a resource, with per-load context."""

    __tablename__ = "stage_resources"

    stage_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("stages.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("resources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The URL this resource was fetched from in the context of this stage
    # (the same bytes can be served from different URLs).
    url: Mapped[str | None] = mapped_column(Text)
    # How the load was initiated: script_src | dynamic | fetch | xhr |
    # css | iframe | ws | inline.
    initiator: Mapped[str | None] = mapped_column(String(16))
    # Which document (main-frame navigation) in the render this belonged
    # to — mirrors Stage.seq / the network log's doc_seq.
    doc_seq: Mapped[int | None] = mapped_column(Integer)
    # Seconds since navigation start when the load completed.
    ts: Mapped[float | None] = mapped_column(Float)

    stage: Mapped[Stage] = relationship(back_populates="stage_resources")
    resource: Mapped[Resource] = relationship(back_populates="stage_resources")

    __table_args__ = (
        Index("ix_stage_resources_stage_seq", "stage_id", "doc_seq"),
    )
