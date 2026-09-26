"""Actor business logic."""

import uuid

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from darla.models.actor import Actor
from darla.models.associations import (
    campaign_actors,
    family_actors,
    kit_actors,
)
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator
from darla.models.kit import Kit


class ActorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_actors(
        self, offset: int = 0, limit: int = 50, include_auto: bool = False
    ) -> tuple[list[Actor], int]:
        """List analyst-managed actors.

        By default, synthetic actors created by the legacy
        ``correlate_kit_actors`` task (``auto_generated=True``) are hidden —
        they're kept in the DB to preserve historical indicator/kit links but
        are not useful in analyst list views.  Pass ``include_auto=True`` to
        see them (debugging, cleanup tooling, reverse-lookup queries).
        """
        query = select(Actor).order_by(Actor.created_at.desc())
        count_query = select(func.count(Actor.id))
        if not include_auto:
            query = query.where(Actor.auto_generated.is_(False))
            count_query = count_query.where(Actor.auto_generated.is_(False))

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_actor(self, actor_id: uuid.UUID) -> Actor | None:
        result = await self.db.execute(
            select(Actor).where(Actor.id == actor_id)
        )
        return result.scalar_one_or_none()

    async def create_actor(self, data: dict) -> Actor:
        actor = Actor(**data)
        self.db.add(actor)
        await self.db.flush()
        return actor

    async def update_actor(
        self, actor_id: uuid.UUID, data: dict,
    ) -> Actor | None:
        """Mutate operator-editable fields.

        ``None`` values are skipped so callers can ``model_dump(exclude_unset=True)``
        to avoid clobbering unspecified fields.  To clear an array
        column (aliases / email_addresses / telegram_handles) callers
        should send an empty list ``[]`` rather than ``null``.

        Refresh after flush so the post-update ``updated_at`` lands in
        memory before pydantic serializes — see the
        MissingGreenlet-on-async-lazyload bug fixed in PR #75.
        """
        actor = await self.get_actor(actor_id)
        if not actor:
            return None
        for key, value in data.items():
            if value is not None:
                setattr(actor, key, value)
        await self.db.flush()
        await self.db.refresh(actor)
        return actor

    async def delete_actor(self, actor_id: uuid.UUID) -> bool:
        actor = await self.get_actor(actor_id)
        if not actor:
            return False
        # Unlink indicators (SET NULL) so FK doesn't block delete
        from sqlalchemy import update

        await self.db.execute(
            update(Indicator)
            .where(Indicator.actor_id == actor_id)
            .values(actor_id=None)
        )
        await self.db.delete(actor)
        await self.db.flush()
        return True

    async def link_indicators(
        self, actor_id: uuid.UUID, indicator_ids: list[uuid.UUID]
    ) -> int:
        result = await self.db.execute(
            select(Indicator).where(Indicator.id.in_(indicator_ids))
        )
        indicators = result.scalars().all()
        count = 0
        for indicator in indicators:
            indicator.actor_id = actor_id
            count += 1
        await self.db.flush()
        return count

    # ---------------------------------------------------------------------
    # Stats — drives the rebuilt actor-detail page's Overview tab.
    # ---------------------------------------------------------------------

    async def get_stats(self, actor_id: uuid.UUID) -> dict | None:
        """Aggregate everything the Overview tab + chart cards need.

        One method bundles all the aggregations rather than 8 separate
        endpoints because the page loads them together — fewer
        round-trips, simpler React Query plumbing, and the queries are
        cheap enough at the 300-samples/day target that a single
        ``stats`` request stays under ~50 ms even with several joins.
        """
        actor = await self.get_actor(actor_id)
        if actor is None:
            return None

        # Counts — straight COUNT(*) against the junctions.
        kit_count = (await self.db.execute(
            select(func.count(kit_actors.c.kit_id))
            .where(kit_actors.c.actor_id == actor_id)
        )).scalar_one()

        campaign_count = (await self.db.execute(
            select(func.count(campaign_actors.c.campaign_id))
            .where(campaign_actors.c.actor_id == actor_id)
        )).scalar_one()

        family_count = (await self.db.execute(
            select(func.count(family_actors.c.family_id))
            .where(family_actors.c.actor_id == actor_id)
        )).scalar_one()

        indicator_count = (await self.db.execute(
            select(func.count(Indicator.id))
            .where(Indicator.actor_id == actor_id)
        )).scalar_one()

        # Computed first/last seen — ``min``/``max`` of kit timestamps.
        # Differs from the operator-editable ``actor.first_seen`` /
        # ``actor.last_seen`` (which are free-form strings).  The
        # computed values are what we display on the Overview header
        # since they're authoritative.
        seen_row = (await self.db.execute(
            select(
                func.min(Kit.created_at).label("first_seen"),
                func.max(Kit.created_at).label("last_seen"),
            )
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .where(kit_actors.c.actor_id == actor_id)
        )).one()

        # Target brand distribution — kits attributed to this actor
        # joined through campaign_kits → campaigns.target_brand.  Top 10
        # to keep the chart readable; everything past 10 collapses to
        # "Other" client-side.
        from darla.models.associations import campaign_kits

        brand_rows = (await self.db.execute(
            select(
                Campaign.target_brand,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .join(campaign_kits, campaign_kits.c.kit_id == Kit.id)
            .join(Campaign, Campaign.id == campaign_kits.c.campaign_id)
            .where(
                kit_actors.c.actor_id == actor_id,
                Campaign.target_brand.is_not(None),
            )
            .group_by(Campaign.target_brand)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Family distribution — same shape, kits → families.
        from darla.models.associations import family_kits

        family_rows = (await self.db.execute(
            select(
                Family.id,
                Family.name,
                func.count(func.distinct(Kit.id)).label("count"),
            )
            .select_from(Kit)
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .join(family_kits, family_kits.c.kit_id == Kit.id)
            .join(Family, Family.id == family_kits.c.family_id)
            .where(kit_actors.c.actor_id == actor_id)
            .group_by(Family.id, Family.name)
            .order_by(desc("count"))
            .limit(10)
        )).all()

        # Timeline — kits per month bucket, last 12 months.  Postgres
        # ``date_trunc`` gives us a clean month-floor without grouping
        # arithmetic in Python.  Caller renders an empty bar for any
        # month with no kits (so the chart x-axis is always 12-wide).
        timeline_rows = (await self.db.execute(
            select(
                func.date_trunc("month", Kit.created_at).label("bucket"),
                func.count(Kit.id).label("count"),
            )
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .where(kit_actors.c.actor_id == actor_id)
            .group_by("bucket")
            .order_by("bucket")
        )).all()

        # Top indicators — most frequent (type, value) pairs across
        # this actor's indicators.  Useful for a "this group's
        # signature TTPs" panel: same telegram handle reused, same
        # OAuth client_id deployed across kits, etc.
        top_indicators = (await self.db.execute(
            select(
                Indicator.type,
                Indicator.value,
                func.count(Indicator.id).label("count"),
            )
            .where(Indicator.actor_id == actor_id)
            .group_by(Indicator.type, Indicator.value)
            .order_by(desc("count"), Indicator.value)
            .limit(20)
        )).all()

        return {
            "kit_count": kit_count,
            "campaign_count": campaign_count,
            "family_count": family_count,
            "indicator_count": indicator_count,
            "first_seen_computed": seen_row.first_seen,
            "last_seen_computed": seen_row.last_seen,
            "target_brand_distribution": [
                {"brand": r.target_brand, "count": r.count}
                for r in brand_rows
            ],
            "family_distribution": [
                {
                    "family_id": r.id,
                    "family_name": r.name,
                    "count": r.count,
                }
                for r in family_rows
            ],
            "timeline": [
                {
                    "month": r.bucket.strftime("%Y-%m") if r.bucket else None,
                    "count": r.count,
                }
                for r in timeline_rows
                if r.bucket is not None
            ],
            "top_indicators": [
                {
                    "type": r.type.value,
                    "value": r.value,
                    "count": r.count,
                }
                for r in top_indicators
            ],
        }

    # ---------------------------------------------------------------------
    # Paginated drill-downs — drive the Kits / Indicators / Campaigns /
    # Families tabs on the rebuilt detail page.
    # ---------------------------------------------------------------------

    async def list_kits(
        self,
        actor_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
        status: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = (
            select(Kit)
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .where(kit_actors.c.actor_id == actor_id)
            .order_by(Kit.created_at.desc())
        )
        count_query = (
            select(func.count(Kit.id))
            .join(kit_actors, kit_actors.c.kit_id == Kit.id)
            .where(kit_actors.c.actor_id == actor_id)
        )
        if status:
            query = query.where(Kit.status == status)
            count_query = count_query.where(Kit.status == status)
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_indicators(
        self,
        actor_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Indicator], int]:
        query = (
            select(Indicator)
            .where(Indicator.actor_id == actor_id)
            .order_by(Indicator.created_at.desc())
        )
        count_query = (
            select(func.count(Indicator.id))
            .where(Indicator.actor_id == actor_id)
        )
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def list_campaigns(
        self, actor_id: uuid.UUID,
    ) -> list[Campaign]:
        """Campaigns linked to this actor.  Not paginated — typical
        actor has < 50 campaigns and the operator wants the whole
        list visible at once."""
        result = await self.db.execute(
            select(Campaign)
            .join(campaign_actors, campaign_actors.c.campaign_id == Campaign.id)
            .where(campaign_actors.c.actor_id == actor_id)
            .order_by(Campaign.name)
        )
        return list(result.scalars().all())

    async def list_families(
        self, actor_id: uuid.UUID,
    ) -> list[Family]:
        """Families linked to this actor.  Same rationale as campaigns
        for skipping pagination."""
        result = await self.db.execute(
            select(Family)
            .join(family_actors, family_actors.c.family_id == Family.id)
            .where(family_actors.c.actor_id == actor_id)
            .order_by(Family.name)
        )
        return list(result.scalars().all())
