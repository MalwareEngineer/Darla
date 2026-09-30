"""Stage / attack-flow API endpoints.

Read-only analytics over the stage model: a single stage's detail and
resources, its same-role near-neighbours across every investigation, the
role clusters (families of bot checks, AiTM backends, …), and the
bot-check × AiTM co-occurrence matrix that surfaces PhaaS mix-and-match.
"""

import uuid

from fastapi import APIRouter, HTTPException, Query

from darla.api.deps import DbSession
from darla.models.stage import StageRole
from darla.schemas.stage import (
    ClusterView,
    CooccurrenceView,
    SimilarStage,
    StageDetail,
    StageResourceView,
)
from darla.services.stage_service import StageService

router = APIRouter()


def _parse_role(value: str) -> StageRole:
    try:
        return StageRole(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"Unknown stage role: {value}",
        ) from exc


@router.get("/clusters", response_model=list[ClusterView])
async def stage_clusters(
    db: DbSession,
    role: str = Query(..., description="Stage role to cluster, e.g. bot_check"),
) -> list[ClusterView]:
    service = StageService(db)
    clusters = await service.cluster_role(_parse_role(role))
    return [ClusterView(**c) for c in clusters]


@router.get("/cooccurrence", response_model=CooccurrenceView)
async def stage_cooccurrence(
    db: DbSession,
    role_a: str = Query("bot_check"),
    role_b: str = Query("cred_capture"),
) -> CooccurrenceView:
    service = StageService(db)
    data = await service.cooccurrence(_parse_role(role_a), _parse_role(role_b))
    return CooccurrenceView(**data)


@router.get("/{stage_id}", response_model=StageDetail)
async def get_stage(stage_id: uuid.UUID, db: DbSession) -> StageDetail:
    service = StageService(db)
    stage = await service.get_stage(stage_id)
    if not stage:
        raise HTTPException(status_code=404, detail="Stage not found")

    resources = []
    for sr in stage.stage_resources:
        res = sr.resource
        resources.append(StageResourceView(
            id=sr.id,
            resource_id=sr.resource_id,
            url=sr.url,
            initiator=sr.initiator,
            doc_seq=sr.doc_seq,
            ts=sr.ts,
            sha256=res.sha256 if res else None,
            content_type=res.content_type if res else None,
            size=res.size if res else None,
        ))

    return StageDetail(
        id=stage.id,
        kit_id=stage.kit_id,
        seq=stage.seq,
        url=stage.url,
        host=stage.host,
        role=stage.role.value,
        nav_method=stage.nav_method,
        screenshot_path=stage.screenshot_path,
        body_path=stage.body_path,
        status_code=stage.status_code,
        content_type=stage.content_type,
        dwell_seconds=stage.dwell_seconds,
        aitm_baseline=stage.aitm_baseline,
        tlsh_raw=stage.tlsh_raw,
        tlsh_rendered=stage.tlsh_rendered,
        skeleton_hash=stage.skeleton_hash,
        request_shape_hash=stage.request_shape_hash,
        screenshot_phash=stage.screenshot_phash,
        fingerprint=stage.fingerprint or {},
        resource_count=len(resources),
        resources=resources,
        created_at=stage.created_at,
    )


@router.get("/{stage_id}/similar", response_model=list[SimilarStage])
async def similar_stages(
    stage_id: uuid.UUID,
    db: DbSession,
    limit: int = Query(50, ge=1, le=200),
) -> list[SimilarStage]:
    service = StageService(db)
    stage = await service.get_stage(stage_id)
    if not stage:
        raise HTTPException(status_code=404, detail="Stage not found")
    matches = await service.find_similar_stages(stage, limit=limit)
    return [SimilarStage(**m) for m in matches]
