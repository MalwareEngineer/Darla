"""Family API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from darla.api.deps import DbSession, Pagination
from darla.auth import require_role
from darla.models import UserRole
from darla.schemas.actor import ActorSummary
from darla.schemas.campaign import CampaignSummary
from darla.schemas.family import (
    FamilyCreate,
    FamilyDetail,
    FamilyListResponse,
    FamilyStats,
    FamilyUpdate,
    FamilyYaraRuleCount,
    LinkActorsRequest,
    LinkKitsRequest,
)
from darla.schemas.indicator import IndicatorListResponse
from darla.schemas.kit import KitListResponse
from darla.services.family_service import FamilyService

router = APIRouter()

# See darla.api.actors for rationale on the shorthand.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]


@router.get("", response_model=FamilyListResponse)
async def list_families(db: DbSession, pagination: Pagination):
    service = FamilyService(db)
    families, total = await service.list_families(
        offset=pagination.offset, limit=pagination.limit
    )
    return FamilyListResponse(items=families, total=total)


@router.post(
    "",
    response_model=FamilyDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=_ANALYST,
)
async def create_family(payload: FamilyCreate, db: DbSession):
    service = FamilyService(db)
    family = await service.create_family(payload.model_dump())
    return family


@router.get("/{family_id}", response_model=FamilyDetail)
async def get_family(family_id: uuid.UUID, db: DbSession):
    service = FamilyService(db)
    family = await service.get_family(family_id)
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")
    return family


@router.put("/{family_id}", response_model=FamilyDetail, dependencies=_ANALYST)
async def update_family(family_id: uuid.UUID, payload: FamilyUpdate, db: DbSession):
    service = FamilyService(db)
    family = await service.update_family(
        family_id, payload.model_dump(exclude_unset=True)
    )
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")
    return family


@router.delete(
    "/{family_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=_ANALYST,
)
async def delete_family(family_id: uuid.UUID, db: DbSession):
    service = FamilyService(db)
    deleted = await service.delete_family(family_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Family not found")


@router.post("/{family_id}/kits", dependencies=_ANALYST)
async def link_kits(
    family_id: uuid.UUID, payload: LinkKitsRequest, db: DbSession
):
    service = FamilyService(db)
    try:
        count = await service.link_kits(family_id, payload.kit_ids)
    except ValueError as e:
        raise HTTPException(status_code=404, detail="Family not found") from e
    return {"added": count}


@router.post("/{family_id}/actors", dependencies=_ANALYST)
async def link_actors(
    family_id: uuid.UUID, payload: LinkActorsRequest, db: DbSession
):
    service = FamilyService(db)
    try:
        count = await service.link_actors(family_id, payload.actor_ids)
    except ValueError as e:
        raise HTTPException(status_code=404, detail="Family not found") from e
    return {"added": count}


# ---------------------------------------------------------------------------
# Stats + drill-down endpoints — power the rebuilt detail page tabs.
# ---------------------------------------------------------------------------


@router.get("/{family_id}/stats", response_model=FamilyStats)
async def get_family_stats(family_id: uuid.UUID, db: DbSession):
    """Aggregate Overview-tab payload: counts, polymorphism,
    target-brand mix, top deploying actors, top YARA rules, monthly
    timeline, top indicators."""
    service = FamilyService(db)
    stats = await service.get_stats(family_id)
    if stats is None:
        raise HTTPException(status_code=404, detail="Family not found")
    return stats


@router.get("/{family_id}/kits", response_model=KitListResponse)
async def list_family_kits(
    family_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
    status: str | None = Query(  # noqa: A002 — matches schema
        default=None, description="Filter by kit status",
    ),
):
    """Paginated kit list for the Kits tab."""
    service = FamilyService(db)
    items, total = await service.list_kits(
        family_id,
        offset=pagination.offset,
        limit=pagination.limit,
        status=status,
    )
    return KitListResponse(items=items, total=total)


@router.get("/{family_id}/indicators", response_model=IndicatorListResponse)
async def list_family_indicators(
    family_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Paginated indicator list for the Indicators tab — IOCs
    extracted from any kit attributed to this family."""
    service = FamilyService(db)
    items, total = await service.list_indicators(
        family_id, offset=pagination.offset, limit=pagination.limit,
    )
    return IndicatorListResponse(items=items, total=total)


@router.get("/{family_id}/yara-rules", response_model=list[FamilyYaraRuleCount])
async def list_family_yara_rules(family_id: uuid.UUID, db: DbSession):
    """YARA rules anchoring this family — aggregated rule-name hit
    counts across the family's kits."""
    service = FamilyService(db)
    return await service.list_yara_rules(family_id)


@router.get("/{family_id}/actors-list", response_model=list[ActorSummary])
async def list_family_actors(family_id: uuid.UUID, db: DbSession):
    """Actors curated as members of this family.  Routed at
    ``/actors-list`` rather than ``/actors`` because the latter is
    the POST link endpoint — giving GET its own path keeps the
    route table unambiguous."""
    service = FamilyService(db)
    return await service.list_actors(family_id)


@router.get("/{family_id}/campaigns", response_model=list[CampaignSummary])
async def list_family_campaigns(family_id: uuid.UUID, db: DbSession):
    """Campaigns sharing at least one kit with this family."""
    service = FamilyService(db)
    return await service.list_campaigns(family_id)
