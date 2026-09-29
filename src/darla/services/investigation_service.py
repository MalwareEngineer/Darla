"""Investigation business logic."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.models.investigation import Investigation, InvestigationStatus
from darla.models.kit import Kit, KitStatus
from darla.services.dispatch import commit_then_dispatch


class InvestigationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_investigations(
        self,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Investigation], int]:
        query = select(Investigation).order_by(Investigation.created_at.desc())
        count_query = select(func.count(Investigation.id))
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_investigation(self, investigation_id: uuid.UUID) -> Investigation | None:
        query = (
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(selectinload(Investigation.root_kit))
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_from_url(
        self, url: str, max_depth: int = 5, prepare=None,
    ) -> tuple[Investigation, Kit, str]:
        """Create an investigation starting from a URL.

        ``prepare(investigation, kit)`` runs before the commit that precedes
        dispatch (see ``kit_service.PrepareKit`` for why that matters).
        """
        kit = Kit(
            id=uuid.uuid4(),
            source_url=url,
            source_feed="investigation",
            status=KitStatus.PENDING,
            chain_depth=0,
        )
        self.db.add(kit)
        await self.db.flush()

        investigation = Investigation(
            id=uuid.uuid4(),
            name=f"URL-{str(kit.id)[:8]}",
            root_kit_id=kit.id,
            status=InvestigationStatus.IN_PROGRESS,
            max_depth=max_depth,
        )
        self.db.add(investigation)
        await self.db.flush()

        kit.investigation_id = investigation.id
        if prepare:
            await prepare(investigation, kit)

        from darla.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = await commit_then_dispatch(self.db, chain)

        return investigation, kit, result.id

    async def create_from_file(
        self,
        kit: Kit,
        max_depth: int = 5,
    ) -> Investigation:
        """Create an investigation from an already-created kit (e.g. .eml or image upload)."""
        # Choose prefix based on file type
        fname = (kit.filename or "").lower()
        image_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
        if any(fname.endswith(ext) for ext in image_exts):
            prefix = "QR"
        elif fname.endswith(".eml"):
            prefix = "EML"
        else:
            prefix = "FILE"
        investigation = Investigation(
            id=uuid.uuid4(),
            name=f"{prefix}-{str(kit.id)[:8]}",
            root_kit_id=kit.id,
            status=InvestigationStatus.IN_PROGRESS,
            max_depth=max_depth,
        )
        self.db.add(investigation)
        await self.db.flush()

        kit.investigation_id = investigation.id
        kit.chain_depth = 0
        return investigation

    async def update_investigation(
        self, investigation_id: uuid.UUID, data: dict
    ) -> Investigation | None:
        investigation = await self.get_investigation(investigation_id)
        if not investigation:
            return None
        for key, value in data.items():
            setattr(investigation, key, value)
        await self.db.flush()
        return investigation

    async def delete_investigation(self, investigation_id: uuid.UUID) -> bool:
        """Delete an investigation.

        The FK graph is cyclic at the ORM level:
          - ``investigations.root_kit_id`` → ``kits.id``  (CASCADE, NOT NULL)
          - ``kits.investigation_id``      → ``investigations.id`` (SET NULL)

        If we mark BOTH the Investigation and its root Kit for ORM deletion
        in the same unit-of-work, SQLAlchemy can't topologically order them
        and raises ``CircularDependencyError``.  Instead, we delete only
        the root kit via ORM and let the DB-level ``ON DELETE CASCADE`` on
        ``investigations.root_kit_id`` drop the investigation row.  The
        Investigation is expunged from the session first so its load does
        not pull it into the pending unit-of-work.

        Cleanup summary:
          - Root kit deleted via :meth:`KitService.delete_kit` (cascades
            descendants + removes on-disk files).
          - Investigation row removed by DB CASCADE when the root kit goes.
          - Non-descendant kits with ``investigation_id`` set keep their
            data; their ``investigation_id`` is nulled via SET NULL.
        """
        investigation = await self.get_investigation(investigation_id)
        if not investigation:
            return False

        root_kit_id = investigation.root_kit_id

        # Detach the Investigation from the session so the root-kit delete
        # doesn't create a DeleteState cycle with it.  DB CASCADE still
        # removes the row when the root kit is deleted.
        self.db.expunge(investigation)
        if investigation.root_kit is not None:
            # selectinload pulled the Kit into the identity map too — get
            # it out of the unit of work before kit_service re-loads it.
            self.db.expunge(investigation.root_kit)

        from darla.services.kit_service import KitService

        kit_service = KitService(self.db)
        await kit_service.delete_kit(root_kit_id)
        return True

    async def get_kit_tree(self, investigation_id: uuid.UUID) -> list[Kit]:
        """Get all kits in an investigation, ordered by depth then created_at."""
        query = (
            select(Kit)
            .where(Kit.investigation_id == investigation_id)
            .order_by(Kit.chain_depth, Kit.created_at)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())
