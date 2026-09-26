"""Victim + observation business logic.

Two entry points live here:

* :func:`observe_victim_email` — the **sync** observation hook called
  from Celery tasks (oauth_ioc extraction, EML recipient parsing,
  AITM url-fragment extraction).  Filters by monitored_domains,
  upserts the Victim row, creates a kit_victims junction row with
  the source channel, and updates first/last_seen.  Returns the
  Victim if promoted; ``None`` if the email's domain isn't on the
  allowlist (caller is responsible for emitting a corresponding
  Indicator row in that case so the intel isn't lost).
* :class:`VictimService` — the **async** CRUD surface used by the
  PhishPrint API endpoints (list, get, update display_name / type /
  notes, query observations).

The split exists because the analysis pipeline is sync (Celery tasks
on a sync SQLAlchemy session) while FastAPI is async.  Each side
gets the right session shape without leaking complexity into the
caller.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload

from darla.models.kit import Kit
from darla.models.monitored_domain import MonitoredDomain
from darla.models.victim import (
    KitVictim,
    Victim,
    VictimObservationSource,
    VictimType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auto-classification — service-account heuristics
# ---------------------------------------------------------------------------

# Local-part values (before the @) that should auto-classify as
# ``service`` so operators don't have to manually triage every
# automated mailer.  Anything not on this list defaults to ``user``;
# operators can re-classify from the victim detail page.
_SERVICE_LOCALS_EXACT: frozenset[str] = frozenset({
    "noreply", "no-reply", "donotreply", "do-not-reply", "do_not_reply",
    "mailer-daemon", "mailerdaemon", "postmaster",
    "automated", "notifications", "alerts", "notify",
    "support-noreply", "info-noreply",
})

# Local-part prefixes that imply automation regardless of suffix.
_SERVICE_LOCAL_PREFIXES: tuple[str, ...] = (
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "mailer-daemon",
)


def classify_email_type(email: str) -> VictimType:
    """Heuristic classification for fresh Victim rows.

    Conservative: only flags the unambiguous ``service`` cases.
    Everything else returns ``user``.  Operators tag exec / distro /
    shared_mailbox manually because those need org context the
    pipeline doesn't have.
    """
    local = email.split("@", 1)[0].lower()
    if local in _SERVICE_LOCALS_EXACT:
        return VictimType.SERVICE
    if any(local.startswith(p) for p in _SERVICE_LOCAL_PREFIXES):
        return VictimType.SERVICE
    return VictimType.USER


# ---------------------------------------------------------------------------
# Sync observation hook — called from Celery tasks
# ---------------------------------------------------------------------------

def _split_email(email_raw: str | None) -> tuple[str, str] | None:
    """Lowercase, strip, validate.  Returns ``(email, domain)`` or
    ``None`` for unparseable input.  Doesn't throw — observation
    callers can pass arbitrary attacker-controlled strings."""
    if not email_raw or not isinstance(email_raw, str):
        return None
    email = email_raw.strip().lower()
    if email.count("@") != 1:
        return None
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        return None
    return email, domain


def _is_monitored_domain(
    monitored: Iterable[str], domain: str,
) -> bool:
    """Suffix-aware match.  ``acme.com`` in the allowlist matches
    both ``acme.com`` and ``sub.acme.com``.  Subsidiaries that don't
    share the parent domain (e.g. ``acme-hr.com``) need their own row.
    """
    domain = domain.lower()
    for md in monitored:
        md_lower = md.lower()
        if domain == md_lower or domain.endswith("." + md_lower):
            return True
    return False


def _load_monitored_domains_sync(db: Session) -> set[str]:
    """Read the allowlist set.  Called once per ``observe`` invocation;
    the caller (a Celery task) is short-lived so caching at the
    process level isn't worth the invalidation complexity."""
    rows = db.execute(select(MonitoredDomain.domain)).all()
    return {row[0].lower() for row in rows}


def observe_victim_email(
    db: Session,
    kit_id: uuid.UUID,
    email_raw: str | None,
    source: VictimObservationSource,
    observed_at: datetime | None = None,
) -> Victim | None:
    """Promote a single observed email to a :class:`Victim` if its
    domain matches a row in :class:`MonitoredDomain`, and record a
    :class:`KitVictim` observation row.

    Returns the Victim on a successful promotion (new or existing),
    or ``None`` when:

      * the email is unparseable (defensive — attacker-controlled
        string),
      * the domain isn't on the monitored allowlist (the caller's
        responsibility from there: emit an :class:`Indicator` row so
        the intel isn't lost),
      * the kit doesn't exist (shouldn't happen but defensive).

    Idempotent: re-observing the same ``(kit_id, victim_id, source)``
    triple is a no-op, which makes this safe to call from chain steps
    that may re-execute on Celery redelivery.

    The session is NOT committed here; the caller's transaction owns
    the commit.  This keeps the observation atomic with whatever
    surrounding work prompted it (e.g. the OAuth IOC extractor's own
    analysis_result write).
    """
    parsed = _split_email(email_raw)
    if parsed is None:
        return None
    email, domain = parsed

    monitored = _load_monitored_domains_sync(db)
    if not _is_monitored_domain(monitored, domain):
        return None

    observed_at = observed_at or datetime.now(UTC)

    # Defensive: kit row must exist for the FK.  In practice the
    # caller is always inside ``download_kit`` / ``parse_eml`` etc.
    # with a valid kit, but we don't want to fail the whole task on
    # a stale callsite.
    kit_exists = db.execute(
        select(Kit.id).where(Kit.id == kit_id)
    ).first()
    if kit_exists is None:
        logger.warning(
            "observe_victim_email: kit %s not found; skipping observation "
            "of %s via %s",
            kit_id, email, source.value,
        )
        return None

    victim = db.execute(
        select(Victim).where(Victim.email == email)
    ).scalar_one_or_none()

    if victim is None:
        victim = Victim(
            email=email,
            domain=domain,
            type=classify_email_type(email),
            first_seen=observed_at,
            last_seen=observed_at,
        )
        db.add(victim)
        db.flush()
    else:
        # Defensive: some DB backends (notably SQLite via the test
        # harness) round-trip ``DateTime(timezone=True)`` columns as
        # tz-naive.  Postgres preserves the tz, but we don't want
        # the comparison to crash when running against anything else.
        # Treat naive timestamps as UTC for the comparison.
        def _aware(dt: datetime | None) -> datetime | None:
            if dt is None:
                return None
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)

        first_aware = _aware(victim.first_seen)
        last_aware = _aware(victim.last_seen)
        if first_aware is None or observed_at < first_aware:
            victim.first_seen = observed_at
        if last_aware is None or observed_at > last_aware:
            victim.last_seen = observed_at

    # Idempotency on (kit, victim, source) triple — re-observation on
    # chain redelivery shouldn't produce duplicate rows.
    existing = db.execute(
        select(KitVictim.id).where(
            KitVictim.kit_id == kit_id,
            KitVictim.victim_id == victim.id,
            KitVictim.source == source,
        )
    ).first()
    if existing is None:
        db.add(KitVictim(
            kit_id=kit_id,
            victim_id=victim.id,
            source=source,
            observed_at=observed_at,
        ))

    return victim


# ---------------------------------------------------------------------------
# Async CRUD service — used by API endpoints
# ---------------------------------------------------------------------------

class VictimService:
    """Async read/write surface for the PhishPrint API endpoints.

    Read methods power the PhishPrint list page (paginated, filtered)
    and the per-victim detail page (with eager-loaded observations).
    Write methods cover the operator-editable fields only —
    ``email`` / ``domain`` / ``first_seen`` / ``last_seen`` are
    pipeline-managed and not user-mutable.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_victims(
        self,
        offset: int = 0,
        limit: int = 50,
        domain: str | None = None,
        type_: VictimType | None = None,
        search: str | None = None,
    ) -> tuple[list[Victim], int]:
        """Paginated list with optional filters.  Default order is by
        ``last_seen`` descending so the most-recently-targeted
        employees float to the top of the PhishPrint dashboard."""
        query = select(Victim)
        count_query = select(func.count(Victim.id))

        if domain:
            domain_lower = domain.lower()
            query = query.where(Victim.domain == domain_lower)
            count_query = count_query.where(Victim.domain == domain_lower)
        if type_ is not None:
            query = query.where(Victim.type == type_)
            count_query = count_query.where(Victim.type == type_)
        if search:
            term = f"%{search.strip().lower()}%"
            # Search across email and display_name; case-insensitive
            # match drives the quick-jump filter on the list page.
            query = query.where(
                func.lower(Victim.email).like(term)
                | func.lower(func.coalesce(Victim.display_name, "")).like(term)
            )
            count_query = count_query.where(
                func.lower(Victim.email).like(term)
                | func.lower(func.coalesce(Victim.display_name, "")).like(term)
            )

        query = query.order_by(
            Victim.last_seen.desc().nullslast(),
            Victim.email,
        )

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_victim(self, victim_id: uuid.UUID) -> Victim | None:
        """Detail load.  Observations are intentionally NOT eager-
        loaded here — the per-victim page fetches them via
        ``list_observations`` so the operator can paginate the kit
        list without dragging the whole junction into memory."""
        result = await self.db.execute(
            select(Victim).where(Victim.id == victim_id)
        )
        return result.scalar_one_or_none()

    async def update_victim(
        self,
        victim_id: uuid.UUID,
        data: dict,
    ) -> Victim | None:
        """Update the operator-editable fields only.  Email, domain,
        and the auto-maintained timestamps are NOT in the allowed
        set; passing them is silently ignored."""
        victim = await self.get_victim(victim_id)
        if victim is None:
            return None
        allowed = {"display_name", "type", "notes"}
        for key, value in data.items():
            if key in allowed:
                setattr(victim, key, value)
        await self.db.flush()
        # The ``updated_at`` column has ``onupdate=now()`` server-side,
        # so the new value lands at the DB layer but the ORM tuple is
        # still expired post-flush.  Pydantic's response serializer
        # would lazy-load it from the DB — which fails with a
        # MissingGreenlet error because we're already in an async
        # context.  Explicitly refresh so the value is in-memory before
        # the response goes out.
        await self.db.refresh(victim)
        return victim

    async def list_observations(
        self,
        victim_id: uuid.UUID,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[KitVictim], int]:
        """Per-victim observation rows joined with kit metadata.

        The selectinload on ``KitVictim.kit`` is what makes the
        per-victim detail page renderable without an N+1 against the
        kits table.
        """
        query = (
            select(KitVictim)
            .where(KitVictim.victim_id == victim_id)
            .options(selectinload(KitVictim.kit))
            .order_by(KitVictim.observed_at.desc())
        )
        count_query = (
            select(func.count(KitVictim.id))
            .where(KitVictim.victim_id == victim_id)
        )
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total
