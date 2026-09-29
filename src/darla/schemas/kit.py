"""Pydantic schemas for Kit API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl

from darla.models.kit import KitStatus


class KitCreate(BaseModel):
    url: HttpUrl
    source_feed: str | None = None
    force: bool = False
    actor_id: uuid.UUID | None = None
    campaign_id: uuid.UUID | None = None
    family_id: uuid.UUID | None = None


class KitSummary(BaseModel):
    id: uuid.UUID
    source_url: str
    sha256: str | None
    tlsh: str | None
    status: KitStatus
    file_size: int | None
    source_feed: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class IndicatorBrief(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    confidence: int

    model_config = {"from_attributes": True}


class AnalysisResultBrief(BaseModel):
    id: uuid.UUID
    analysis_type: str
    result_data: dict = {}
    duration_seconds: float | None
    files_processed: int | None
    error: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class CampaignBrief(BaseModel):
    id: uuid.UUID
    name: str
    target_brand: str | None = None

    model_config = {"from_attributes": True}


class FamilyBrief(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class ActorBrief(BaseModel):
    id: uuid.UUID
    name: str

    model_config = {"from_attributes": True}


class KitDetail(KitSummary):
    md5: str | None
    sha1: str | None
    filename: str | None
    mime_type: str | None
    error_message: str | None
    parent_kit_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    chain_depth: int = 0
    discovery_method: str | None = None
    indicators: list[IndicatorBrief] = []
    analysis_results: list[AnalysisResultBrief] = []
    campaigns: list[CampaignBrief] = []
    families: list[FamilyBrief] = []
    actors: list[ActorBrief] = []
    child_kits: list[KitSummary] = []

    model_config = {"from_attributes": True}


class KitListResponse(BaseModel):
    items: list[KitSummary]
    total: int


class KitSubmitResponse(BaseModel):
    kit_id: uuid.UUID
    task_id: str
    duplicate: bool = False
    message: str = "Kit submitted for analysis"


class KitBulkCreate(BaseModel):
    urls: list[HttpUrl]
    source_feed: str | None = None
    actor_id: uuid.UUID | None = None
    campaign_id: uuid.UUID | None = None
    family_id: uuid.UUID | None = None


class KitBulkResult(BaseModel):
    url: str
    kit_id: uuid.UUID
    task_id: str | None = None
    duplicate: bool = False


class KitBulkResponse(BaseModel):
    submitted: int
    skipped_duplicate: int
    results: list[KitBulkResult]


class KitBulkUploadResult(BaseModel):
    filename: str
    kit_id: uuid.UUID
    task_id: str | None = None
    investigation_id: uuid.UUID | None = None


class KitBulkUploadResponse(BaseModel):
    submitted: int
    results: list[KitBulkUploadResult]


class SimilarKit(BaseModel):
    id: uuid.UUID
    sha256: str | None
    tlsh: str | None
    source_url: str
    distance: int


class KitDeletePreview(BaseModel):
    kit_id: uuid.UUID
    total_kits: int
    child_kits: int
    indicators: int
    analysis_results: int
    campaign_links: int
    investigations: int


class KitContentFile(BaseModel):
    filename: str
    content: str
    size: int
    mime_type: str | None = None
    truncated: bool = False


class KitContentResponse(BaseModel):
    kit_id: uuid.UUID
    files: list[KitContentFile]


# ── Browser artifacts ──


class ScreenshotItem(BaseModel):
    filename: str
    stage: str
    data_uri: str


class ScreenshotsResponse(BaseModel):
    screenshots: list[ScreenshotItem]


class NetworkLogResponse(BaseModel):
    events: list[dict]
    total: int


class BrowserResourceItem(BaseModel):
    filename: str
    size: int
    mime_type: str | None = None
    content: str | None = None
    truncated: bool = False
    # From _browser_resources/_manifest.json — where the capture came from.
    url: str | None = None
    status: int | None = None
    method: str | None = None
    timestamp: float | None = None
    request_id: int | None = None


class BrowserResourcesResponse(BaseModel):
    resources: list[BrowserResourceItem]


class DeobfuscationPairItem(BaseModel):
    file: str
    deob_file: str
    layers: int = 0
    techniques: list[str] = []
    original_content: str | None = None
    original_truncated: bool = False
    deob_content: str | None = None
    deob_truncated: bool = False


class DeobfuscationPreviewResponse(BaseModel):
    pairs: list[DeobfuscationPairItem]
