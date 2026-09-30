"""Pydantic schemas for the stage / attack-flow API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class StageResourceView(BaseModel):
    id: uuid.UUID
    resource_id: uuid.UUID
    url: str | None = None
    initiator: str | None = None
    doc_seq: int | None = None
    ts: float | None = None
    sha256: str | None = None
    content_type: str | None = None
    size: int | None = None

    model_config = {"from_attributes": True}


class StageSummary(BaseModel):
    id: uuid.UUID
    kit_id: uuid.UUID
    seq: int
    url: str | None = None
    host: str | None = None
    role: str
    nav_method: str | None = None
    screenshot_path: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    dwell_seconds: float | None = None
    aitm_baseline: str | None = None
    resource_count: int = 0

    model_config = {"from_attributes": True}


class StageDetail(StageSummary):
    body_path: str | None = None
    tlsh_raw: str | None = None
    tlsh_rendered: str | None = None
    skeleton_hash: str | None = None
    request_shape_hash: str | None = None
    screenshot_phash: str | None = None
    fingerprint: dict = {}
    resources: list[StageResourceView] = []
    created_at: datetime | None = None


class SimilarStage(BaseModel):
    stage_id: str
    kit_id: str
    url: str | None = None
    host: str | None = None
    role: str
    score: float
    verdict: str
    comparison: dict


class ClusterView(BaseModel):
    cluster_id: str
    role: str
    size: int
    stage_ids: list[str]
    hosts: list[str]


class CooccurrenceView(BaseModel):
    role_a: str
    role_b: str
    clusters_a: list[ClusterView]
    clusters_b: list[ClusterView]
    matrix: dict[str, dict[str, int]]


class FlowStageNode(BaseModel):
    """A stage as it appears in an investigation's flow view."""

    id: uuid.UUID
    kit_id: uuid.UUID
    seq: int
    url: str | None = None
    host: str | None = None
    role: str
    nav_method: str | None = None
    screenshot_path: str | None = None
    dwell_seconds: float | None = None
    aitm_baseline: str | None = None
    resource_count: int = 0

    model_config = {"from_attributes": True}


class FlowKitNode(BaseModel):
    """A kit (render/download) in the flow, carrying its ordered stages."""

    kit_id: uuid.UUID
    source_url: str
    discovery_method: str | None = None
    chain_depth: int = 0
    status: str
    stages: list[FlowStageNode] = []
    children: list[FlowKitNode] = []


class FlowDiffPair(BaseModel):
    kind: str                       # match | only_a | only_b
    role: str | None = None
    a_stage_id: str | None = None
    b_stage_id: str | None = None
    a_host: str | None = None
    b_host: str | None = None
    comparison: dict | None = None


class FlowDiffResponse(BaseModel):
    investigation_a: uuid.UUID
    investigation_b: uuid.UUID
    pairs: list[FlowDiffPair]
