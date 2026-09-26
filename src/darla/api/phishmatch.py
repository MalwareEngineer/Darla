"""PhishMatch API — similarity-scored attribution suggestions.

Three endpoints:

- ``GET  /phishmatch/kit/{kit_id}``                 — rank candidate
  actors/families/campaigns for an unattributed (or curious) kit.
- ``GET  /phishmatch/entity/{entity_type}/{id}``    — reverse lookup:
  unattributed kits that score high against an attributed entity.
- ``POST /phishmatch/kit/{kit_id}/attribute``       — write an attribution
  (kit → entity link) along with the evidence snapshot.  This is how the
  PhishMatch UI commits an analyst's decision.

The scoring engine itself is sync (see ``darla.analysis.phishmatch``); we
run it in a threadpool from the async route to avoid blocking the event
loop.  The attribution write is done with the async session because it's
simple, small, and belongs in the request's transaction.
"""

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update

from darla.analysis.phishmatch import (
    MIN_SURFACE_SCORE,
    PhishMatchScorer,
)
from darla.api.deps import DbSession
from darla.auth import require_role
from darla.database import get_sync_db
from darla.models import UserRole
from darla.models.actor import Actor
from darla.models.associations import (
    CONFIDENCE_VALUES,
    campaign_kits,
    family_kits,
    kit_actors,
)
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.kit import Kit

router = APIRouter()

# See darla.api.actors for rationale on the shorthand.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]


EntityTypeLit = Literal["actor", "family", "campaign"]


# ---------------------------------------------------------------------------
# Response / request schemas
# ---------------------------------------------------------------------------


class PhishMatchResponse(BaseModel):
    kit_id: str
    actors: list[dict]
    families: list[dict]
    campaigns: list[dict]
    no_matches_reason: str | None = None
    min_surface_score: float = Field(
        default=MIN_SURFACE_SCORE,
        description=(
            "Candidates scoring below this are hidden.  Shown so the UI "
            "can explain threshold decisions."
        ),
    )


class ReverseSuggestionsResponse(BaseModel):
    entity_type: EntityTypeLit
    entity_id: str
    suggestions: list[dict]


class AttributeRequest(BaseModel):
    entity_type: EntityTypeLit
    entity_id: uuid.UUID
    confidence: str = Field(
        description="'verified' or 'suspected'.",
        examples=["verified", "suspected"],
    )
    attributed_by: str | None = Field(
        default=None,
        description=(
            "Analyst username.  Optional: we don't have auth yet so the "
            "UI is free to pass a placeholder."
        ),
    )
    evidence_snapshot: dict | None = Field(
        default=None,
        description=(
            "The ``signals`` object from a prior PhishMatch response, "
            "captured at the moment the analyst decided.  Stored verbatim "
            "on the junction row for audit."
        ),
    )


class AttributeResponse(BaseModel):
    kit_id: str
    entity_type: EntityTypeLit
    entity_id: str
    created: bool
    confidence: str
    attributed_at: datetime


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/kit/{kit_id}", response_model=PhishMatchResponse)
async def phishmatch_for_kit(kit_id: uuid.UUID):
    """Rank candidate entities for ``kit_id``."""

    def _score() -> dict:
        db = get_sync_db()
        try:
            result = PhishMatchScorer(db).score_kit(kit_id)
            return result.as_dict()
        finally:
            db.close()

    data = await run_in_threadpool(_score)
    # Pydantic wants a native dict here (we already serialized above).
    return PhishMatchResponse(**data)


@router.get(
    "/entity/{entity_type}/{entity_id}",
    response_model=ReverseSuggestionsResponse,
)
async def phishmatch_suggestions_for_entity(
    entity_type: EntityTypeLit,
    entity_id: uuid.UUID,
    limit: int = 20,
):
    """Reverse lookup — unattributed kits scoring high against ``entity_id``."""

    def _suggest() -> list[dict]:
        db = get_sync_db()
        try:
            return PhishMatchScorer(db).suggest_kits_for_entity(
                entity_type=entity_type,
                entity_id=entity_id,
                limit=limit,
            )
        finally:
            db.close()

    suggestions = await run_in_threadpool(_suggest)
    return ReverseSuggestionsResponse(
        entity_type=entity_type,
        entity_id=str(entity_id),
        suggestions=suggestions,
    )


@router.post(
    "/kit/{kit_id}/attribute",
    response_model=AttributeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=_ANALYST,
)
async def attribute_kit(
    kit_id: uuid.UUID, payload: AttributeRequest, db: DbSession
):
    """Create (or update) the junction link between a kit and an entity.

    Idempotent: re-posting the same ``(kit, entity)`` pair updates the
    evidence snapshot and confidence instead of erroring.  This lets the
    UI "promote" a previously suspected link to verified without first
    deleting it.
    """
    if payload.confidence not in CONFIDENCE_VALUES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"confidence must be one of {sorted(CONFIDENCE_VALUES)}; "
                f"got {payload.confidence!r}"
            ),
        )

    # Sanity: kit and target entity must exist.
    kit = (await db.execute(select(Kit).where(Kit.id == kit_id))).scalar_one_or_none()
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")

    table, entity_col_name, entity_model = _resolve_junction(payload.entity_type)
    entity = (
        await db.execute(
            select(entity_model).where(entity_model.id == payload.entity_id)
        )
    ).scalar_one_or_none()
    if not entity:
        raise HTTPException(
            status_code=404,
            detail=f"{payload.entity_type.capitalize()} not found",
        )

    now = datetime.now(UTC)
    values = {
        "kit_id": kit_id,
        entity_col_name: payload.entity_id,
        "attributed_by": payload.attributed_by,
        "attributed_at": now,
        "confidence": payload.confidence,
        "evidence_snapshot": payload.evidence_snapshot,
    }

    # Is there already a row?
    existing = await db.execute(
        select(table).where(
            table.c.kit_id == kit_id,
            getattr(table.c, entity_col_name) == payload.entity_id,
        )
    )
    if existing.first():
        # Update the evidence/confidence.
        await db.execute(
            update(table)
            .where(
                table.c.kit_id == kit_id,
                getattr(table.c, entity_col_name) == payload.entity_id,
            )
            .values(
                attributed_by=payload.attributed_by,
                attributed_at=now,
                confidence=payload.confidence,
                evidence_snapshot=payload.evidence_snapshot,
            )
        )
        created = False
    else:
        await db.execute(insert(table).values(**values))
        created = True

    await db.commit()

    return AttributeResponse(
        kit_id=str(kit_id),
        entity_type=payload.entity_type,
        entity_id=str(payload.entity_id),
        created=created,
        confidence=payload.confidence,
        attributed_at=now,
    )


@router.delete(
    "/kit/{kit_id}/attribute",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=_ANALYST,
)
async def unattribute_kit(
    kit_id: uuid.UUID,
    entity_type: EntityTypeLit,
    entity_id: uuid.UUID,
    db: DbSession,
):
    """Remove a kit → entity link.  Analysts use this to un-attribute
    after a PhishMatch false positive."""
    table, entity_col_name, _ = _resolve_junction(entity_type)
    result = await db.execute(
        table.delete().where(
            table.c.kit_id == kit_id,
            getattr(table.c, entity_col_name) == entity_id,
        )
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Link not found")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_junction(entity_type: EntityTypeLit):
    """Return (junction_table, entity_fk_column_name, entity_model)."""
    if entity_type == "actor":
        return kit_actors, "actor_id", Actor
    if entity_type == "family":
        return family_kits, "family_id", Family
    if entity_type == "campaign":
        return campaign_kits, "campaign_id", Campaign
    raise HTTPException(status_code=400, detail=f"Unknown entity_type: {entity_type}")
