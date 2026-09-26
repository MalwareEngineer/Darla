"""Pydantic schemas for Victim and MonitoredDomain API endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from darla.models.victim import VictimObservationSource, VictimType

# ---------------------------------------------------------------------------
# MonitoredDomain
# ---------------------------------------------------------------------------

class MonitoredDomainCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    description: str | None = None


class MonitoredDomainUpdate(BaseModel):
    domain: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = None


class MonitoredDomainOut(BaseModel):
    id: uuid.UUID
    domain: str
    description: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MonitoredDomainListResponse(BaseModel):
    items: list[MonitoredDomainOut]
    total: int


# ---------------------------------------------------------------------------
# Victim
# ---------------------------------------------------------------------------

class VictimUpdate(BaseModel):
    """Operator-editable fields only.  ``email`` and ``domain`` are
    pipeline-managed; ``first_seen`` / ``last_seen`` are derived from
    observations."""
    display_name: str | None = Field(default=None, max_length=255)
    type: VictimType | None = None
    notes: str | None = None


class VictimSummary(BaseModel):
    id: uuid.UUID
    email: EmailStr
    domain: str
    display_name: str | None
    type: VictimType
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class VictimDetail(VictimSummary):
    notes: str | None
    updated_at: datetime

    model_config = {"from_attributes": True}


class VictimListResponse(BaseModel):
    items: list[VictimSummary]
    total: int


# ---------------------------------------------------------------------------
# KitVictim observations — for the per-victim detail page
# ---------------------------------------------------------------------------

class _ObservationKit(BaseModel):
    """Trimmed Kit summary for the observation-list view.  Keep the
    fields tight here — the per-victim page renders potentially
    hundreds of these and we don't need the full kit shape."""
    id: uuid.UUID
    source_url: str
    status: str
    sha256: str | None
    chain_depth: int

    model_config = {"from_attributes": True}


class VictimObservationOut(BaseModel):
    id: uuid.UUID
    kit_id: uuid.UUID
    source: VictimObservationSource
    observed_at: datetime
    kit: _ObservationKit

    model_config = {"from_attributes": True}


class VictimObservationListResponse(BaseModel):
    items: list[VictimObservationOut]
    total: int
