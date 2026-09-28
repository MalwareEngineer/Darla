"""Pydantic schemas for Investigation API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl

from darla.schemas.kit import KitSummary


class InvestigationCreate(BaseModel):
    name: str
    url: HttpUrl | None = None
    max_depth: int = 5
    actor_id: uuid.UUID | None = None
    campaign_id: uuid.UUID | None = None
    family_id: uuid.UUID | None = None


class InvestigationSummary(BaseModel):
    id: uuid.UUID
    name: str | None
    description: str | None = None
    status: str
    max_depth: int
    total_kits: int
    total_depth_reached: int
    created_at: datetime

    model_config = {"from_attributes": True}


class InvestigationDetail(InvestigationSummary):
    root_kit: KitSummary | None = None

    model_config = {"from_attributes": True}


class InvestigationUpdate(BaseModel):
    description: str | None = None


class InvestigationTreeNode(BaseModel):
    kit: KitSummary
    discovery_method: str | None = None
    chain_depth: int = 0
    children: list["InvestigationTreeNode"] = []
    # For browser_render kits: ordered distinct hosts the browser navigated
    # through during the render (lure → gate → credential page).  A render
    # is stored as one node whose URL is only its final landing, so this
    # shows the steps the single node collapsed.  None for non-render kits.
    nav_path: list[str] | None = None

    model_config = {"from_attributes": True}


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int


class InvestigationSubmitResponse(BaseModel):
    investigation_id: uuid.UUID
    kit_id: uuid.UUID
    task_id: str
    message: str = "Investigation started"
