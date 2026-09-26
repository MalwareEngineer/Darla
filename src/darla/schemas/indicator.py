"""Pydantic schemas for Indicator API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from darla.models.indicator import IndicatorType


class IndicatorSummary(BaseModel):
    id: uuid.UUID
    type: IndicatorType
    value: str
    confidence: int
    source_file: str | None
    # Source line the IOC came from (capped at 200 chars at extraction).
    # The indicators list renders it under each value.
    context: str | None = None
    kit_id: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}


class IndicatorDetail(IndicatorSummary):
    actor_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class IndicatorListResponse(BaseModel):
    items: list[IndicatorSummary]
    total: int


class IndicatorStats(BaseModel):
    type: str
    count: int
