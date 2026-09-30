"""Stage model — one page the victim's browser actually lands on.

A phishing attack flow is a sequence of *stages*: the lure link, a
redirector, a Cloudflare/bot check, a "preparing your session"
interstitial, an email gate, the final credential-capture (often an AiTM
proxy) page, and — when a token is burned or the ASN looks like a
datacentre — a decoy.  Historically Darla stored a whole browser render
as a single :class:`~darla.models.kit.Kit` whose URL was only the *final*
landing, so the intermediate pages the victim was walked through were
invisible and could not be compared across investigations.

A ``Stage`` is a lighter-weight unit than a Kit: it does not go through
the Celery analysis chain.  Instead its fingerprints (raw/rendered TLSH,
tag-skeleton hash, script-set, request-shape, screenshot pHash) are
computed once, at render-finalise time, by
:mod:`darla.analysis.stage_fingerprint`.  Comparison is then role-scoped
— a bot check is only ever compared against other bot checks — which is
what lets Darla answer "do these two investigations share a bot check but
diverge at the AiTM proxy?".

Each stage belongs to exactly one Kit (the render or httpx download that
observed it) and links to the content-addressed :class:`Resource` rows
for the scripts/CSS/XHR it loaded, via ``stage_resources``.
"""

from __future__ import annotations

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from darla.models.kit import Kit
    from darla.models.resource import StageResource

# JSONB in production (Postgres); portable JSON under SQLite test harnesses.
_JSON = JSONB().with_variant(JSON(), "sqlite")


class StageRole(enum.StrEnum):
    """The function a stage serves in the attack flow.

    Roles are inferred from render-time signals (bot-gate detection,
    Turnstile presence, CTA/email-gate interaction, password fields, IdP
    markers, known decoy hosts, dwell time before redirect).  ``UNKNOWN``
    is the honest default when no classifier fires — never guessed.
    """

    LURE = "lure"                 # the entry URL the victim clicked
    REDIRECTOR = "redirector"     # pure hop (3xx / click-tracker / shortener)
    BOT_CHECK = "bot_check"       # Turnstile / custom PoW / "verify you're human"
    INTERSTITIAL = "interstitial"  # "preparing secure session" / spinner delay
    EMAIL_GATE = "email_gate"     # "enter the email this was sent to"
    CRED_CAPTURE = "cred_capture"  # the fake login / AiTM proxy page
    DECOY = "decoy"               # benign site served after a burned token / cloak
    POST_SUBMIT = "post_submit"   # "success" / redirect-to-real-site after capture
    UNKNOWN = "unknown"


class Stage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "stages"

    kit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Order within the render.  ``seq`` mirrors the browser's main-frame
    # navigation counter (``doc_seq`` in the network log): seq 0 is the
    # first document, incrementing on each top-level navigation.
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    url: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    role: Mapped[StageRole] = mapped_column(
        Enum(StageRole), default=StageRole.UNKNOWN, index=True
    )

    # How the victim *arrived* at this stage from the previous one:
    # http_3xx, meta_refresh, js_location, turnstile_solved, gate_solved,
    # cta_click, form_submit, initial.  Display-only edge label.
    nav_method: Mapped[str | None] = mapped_column(String(32))

    # Relative paths (under the kit's download dir) to this stage's saved
    # page body and screenshot.  Nullable — a pure 3xx redirector has no
    # body worth keeping, and screenshots are best-effort.
    body_path: Mapped[str | None] = mapped_column(Text)
    screenshot_path: Mapped[str | None] = mapped_column(Text)

    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(128))

    # --- Fingerprints (see darla.analysis.stage_fingerprint) ---
    # TLSH of the raw server response body (before JS runs).
    tlsh_raw: Mapped[str | None] = mapped_column(String(72), index=True)
    # TLSH of the rendered, normalised DOM (after JS runs, victim tokens
    # stripped).  For cred_capture stages this may be baseline-subtracted.
    tlsh_rendered: Mapped[str | None] = mapped_column(String(72), index=True)
    # Hash of the tag-path skeleton — same layout even when class names,
    # ids and text rotate per victim.
    skeleton_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    # Hash of the normalised request-sequence shape (method + path
    # template + ws) — the backend protocol fingerprint.
    request_shape_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    # Perceptual hash of the screenshot (64-bit dhash, hex).  Catches
    # pages that look identical but are built differently, and vice versa.
    screenshot_phash: Mapped[str | None] = mapped_column(String(32), index=True)
    # When this is a cred_capture stage whose fingerprint was computed
    # against a known-IdP baseline, the baseline name (e.g. "microsoft").
    # None when no baseline applied.
    aitm_baseline: Mapped[str | None] = mapped_column(String(64))

    # Coarse TLSH bucket (leading nibbles) for cheap candidate filtering
    # before a full distance compare — a poor-man's LSH so similarity
    # queries don't full-scan the stages table.
    tlsh_bucket: Mapped[str | None] = mapped_column(String(8), index=True)

    # Full computed fingerprint: script sha256 set, ws/exfil endpoints,
    # path templates, dwell time, dominant text, gate markers, etc.
    fingerprint: Mapped[dict] = mapped_column(_JSON, default=dict)

    # Dwell time (seconds) the browser spent on this stage before the
    # next navigation — a redirector is sub-second, an interstitial 2-3s.
    dwell_seconds: Mapped[float | None] = mapped_column(Float)

    # Relationships
    kit: Mapped[Kit] = relationship(back_populates="stages")
    stage_resources: Mapped[list[StageResource]] = relationship(
        back_populates="stage",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="StageResource.doc_seq",
    )

    __table_args__ = (
        Index("ix_stages_kit_seq", "kit_id", "seq"),
        Index("ix_stages_role_bucket", "role", "tlsh_bucket"),
    )
