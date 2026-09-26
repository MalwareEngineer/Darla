"""Kit API endpoints."""

import contextlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, status

from darla.api.deps import DbSession, Pagination
from darla.auth import require_role
from darla.config import get_settings
from darla.models import UserRole
from darla.schemas.kit import (
    BrowserResourcesResponse,
    DeobfuscationPreviewResponse,
    KitBulkCreate,
    KitBulkResponse,
    KitBulkResult,
    KitBulkUploadResponse,
    KitBulkUploadResult,
    KitContentResponse,
    KitCreate,
    KitDeletePreview,
    KitDetail,
    KitListResponse,
    KitSubmitResponse,
    NetworkLogResponse,
    ScreenshotsResponse,
    SimilarKit,
)
from darla.services.kit_service import KitService

router = APIRouter()

# See darla.api.actors for rationale on the shorthand.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]

# Uploads that may spawn child kits get an auto-created investigation:
# .eml (clickable links) and images (QR codes).
_IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"})


async def _link_kit_to_entities(
    db,
    kit_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    campaign_id: uuid.UUID | None = None,
    family_id: uuid.UUID | None = None,
) -> None:
    """Link a kit to actor, campaign, and/or family after creation."""
    if campaign_id:
        from darla.services.campaign_service import CampaignService

        campaign_svc = CampaignService(db)
        with contextlib.suppress(ValueError):
            await campaign_svc.add_kits(campaign_id, [kit_id])

    if family_id:
        from darla.services.family_service import FamilyService

        family_svc = FamilyService(db)
        with contextlib.suppress(ValueError):
            await family_svc.link_kits(family_id, [kit_id])

    if actor_id:
        from sqlalchemy import select

        from darla.models.actor import Actor
        from darla.models.kit import Kit

        kit = (await db.execute(select(Kit).where(Kit.id == kit_id))).scalar_one_or_none()
        actor = (await db.execute(select(Actor).where(Actor.id == actor_id))).scalar_one_or_none()
        if kit and actor and actor not in kit.actors:
            kit.actors.append(actor)
            await db.flush()


@router.get("", response_model=KitListResponse)
async def list_kits(
    db: DbSession,
    pagination: Pagination,
    status_filter: str | None = None,
    source_feed: str | None = None,
) -> KitListResponse:
    service = KitService(db)
    kits, total = await service.list_kits(
        offset=pagination.offset,
        limit=pagination.limit,
        status_filter=status_filter,
        source_feed=source_feed,
    )
    return KitListResponse(items=kits, total=total)


@router.post(
    "",
    response_model=KitSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def create_kit(payload: KitCreate, db: DbSession) -> KitSubmitResponse:
    service = KitService(db)
    kit, task_id, duplicate = await service.submit_kit(
        str(payload.url), payload.source_feed, force=payload.force,
    )

    # Auto-create investigation for manual submissions so crawl_chain fires
    if not duplicate and (payload.source_feed or "manual") == "manual":
        from darla.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        await inv_service.create_from_file(kit)

    # Link to actor/campaign/family if specified
    if not duplicate:
        await _link_kit_to_entities(
            db, kit.id, payload.actor_id, payload.campaign_id, payload.family_id,
        )

    return KitSubmitResponse(
        kit_id=kit.id,
        task_id=task_id or "",
        duplicate=duplicate,
        message="Duplicate — existing kit returned" if duplicate else "Kit submitted for analysis",
    )


@router.post(
    "/upload",
    response_model=KitSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def upload_kit(
    db: DbSession,
    file: UploadFile,
    source_feed: str = Form("manual"),
    actor_id: str | None = Form(None),
    campaign_id: str | None = Form(None),
    family_id: str | None = Form(None),
) -> KitSubmitResponse:
    """Upload a local phishing kit file for analysis (skips download step)."""
    settings = get_settings()
    max_bytes = settings.max_kit_size_mb * 1024 * 1024

    # Read file content with size check
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_kit_size_mb}MB limit",
        )

    # Save to download dir so the chain can find it
    kit_id = uuid.uuid4()
    download_dir = Path(settings.kit_download_dir) / str(kit_id)
    download_dir.mkdir(parents=True, exist_ok=True)
    filepath = download_dir / (file.filename or "upload.bin")
    filepath.write_bytes(content)

    service = KitService(db)
    kit, task_id = await service.submit_file(
        filename=file.filename or "upload.bin",
        local_path=str(filepath),
        source_feed=source_feed,
        kit_id=kit_id,
    )

    # Auto-create investigation for uploads that may spawn child kits:
    #  - .eml files (contain clickable links)
    #  - Image files (may contain QR codes with phishing URLs)
    filename_lower = (file.filename or "").lower()
    needs_investigation = filename_lower.endswith(".eml") or any(
        filename_lower.endswith(ext) for ext in _IMAGE_EXTS
    )
    if needs_investigation:
        from darla.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        await inv_service.create_from_file(kit)

    # Link to actor/campaign/family if specified
    await _link_kit_to_entities(
        db, kit.id,
        uuid.UUID(actor_id) if actor_id else None,
        uuid.UUID(campaign_id) if campaign_id else None,
        uuid.UUID(family_id) if family_id else None,
    )

    return KitSubmitResponse(kit_id=kit.id, task_id=task_id)


@router.post(
    "/upload/bulk",
    response_model=KitBulkUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def bulk_upload_kits(
    db: DbSession,
    files: list[UploadFile],
    actor_id: str | None = Form(None),
    campaign_id: str | None = Form(None),
    family_id: str | None = Form(None),
) -> KitBulkUploadResponse:
    """Upload multiple phishing kit files for analysis (max 50)."""
    if len(files) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 files per bulk upload",
        )

    settings = get_settings()
    max_bytes = settings.max_kit_size_mb * 1024 * 1024
    file_entries: list[dict] = []

    for file in files:
        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File '{file.filename}' exceeds {settings.max_kit_size_mb}MB limit",
            )

        kit_id = uuid.uuid4()
        download_dir = Path(settings.kit_download_dir) / str(kit_id)
        download_dir.mkdir(parents=True, exist_ok=True)
        filepath = download_dir / (file.filename or "upload.bin")
        filepath.write_bytes(content)

        file_entries.append({
            "kit_id": kit_id,
            "filename": file.filename or "upload.bin",
            "local_path": str(filepath),
        })

    service = KitService(db)
    results = await service.submit_bulk_files(file_entries)

    # Auto-create investigations for .eml uploads
    from darla.services.investigation_service import InvestigationService

    inv_service = InvestigationService(db)
    final_results: list[KitBulkUploadResult] = []

    for entry, result in zip(file_entries, results, strict=False):
        investigation_id = None
        fname = entry["filename"].lower()
        needs_inv = fname.endswith(".eml") or any(
            fname.endswith(ext) for ext in _IMAGE_EXTS
        )
        if needs_inv:
            kit = await service.get_kit(result["kit_id"])
            if kit:
                inv = await inv_service.create_from_file(kit)
                investigation_id = inv.id if inv else None

        final_results.append(KitBulkUploadResult(
            filename=result["filename"],
            kit_id=result["kit_id"],
            task_id=result["task_id"],
            investigation_id=investigation_id,
        ))

    # Link all uploaded kits to actor/campaign/family if specified
    parsed_actor = uuid.UUID(actor_id) if actor_id else None
    parsed_campaign = uuid.UUID(campaign_id) if campaign_id else None
    parsed_family = uuid.UUID(family_id) if family_id else None
    if parsed_actor or parsed_campaign or parsed_family:
        for r in final_results:
            await _link_kit_to_entities(
                db, r.kit_id, parsed_actor, parsed_campaign, parsed_family,
            )

    return KitBulkUploadResponse(
        submitted=len(final_results),
        results=final_results,
    )


@router.post(
    "/bulk",
    response_model=KitBulkResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def bulk_submit(payload: KitBulkCreate, db: DbSession) -> KitBulkResponse:
    """Submit multiple URLs for download and analysis."""
    if len(payload.urls) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 500 URLs per bulk request",
        )

    service = KitService(db)
    results, submitted, skipped = await service.submit_bulk(
        [str(u) for u in payload.urls], payload.source_feed
    )

    # Auto-create investigations for manual bulk submissions
    if (payload.source_feed or "manual") == "manual":
        from darla.services.investigation_service import InvestigationService

        inv_service = InvestigationService(db)
        for r in results:
            if not r["duplicate"]:
                kit = await service.get_kit(r["kit_id"])
                if kit:
                    await inv_service.create_from_file(kit)

    # Link all submitted kits to actor/campaign/family if specified
    if payload.actor_id or payload.campaign_id or payload.family_id:
        for r in results:
            if not r.get("duplicate"):
                await _link_kit_to_entities(
                    db, r["kit_id"], payload.actor_id, payload.campaign_id, payload.family_id,
                )

    return KitBulkResponse(
        submitted=submitted,
        skipped_duplicate=skipped,
        results=[KitBulkResult(**r) for r in results],
    )


@router.get("/search")
async def search_kits(
    db: DbSession,
    pagination: Pagination,
    q: str | None = None,
    yara_rule: str | None = None,
    tlsh: str | None = None,
    tlsh_threshold: int = 100,
):
    service = KitService(db)
    items, total = await service.search_kits(
        q=q,
        yara_rule=yara_rule,
        tlsh_hash=tlsh,
        tlsh_threshold=tlsh_threshold,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    return {"items": items, "total": total}


@router.post("/bulk-delete", dependencies=_ANALYST)
async def bulk_delete_kits(payload: dict, db: DbSession):
    """Delete multiple kits by ID."""
    ids = payload.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")

    service = KitService(db)
    deleted = 0
    for raw_id in ids:
        try:
            kit_id = uuid.UUID(str(raw_id))
        except ValueError:
            continue
        if await service.delete_kit(kit_id):
            deleted += 1
    await db.commit()
    return {"deleted": deleted}


@router.get("/{kit_id}", response_model=KitDetail)
async def get_kit(kit_id: uuid.UUID, db: DbSession) -> KitDetail:
    service = KitService(db)
    kit = await service.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")
    return KitDetail.model_validate(kit)


@router.get("/{kit_id}/delete-preview", response_model=KitDeletePreview)
async def delete_preview(kit_id: uuid.UUID, db: DbSession) -> KitDeletePreview:
    service = KitService(db)
    preview = await service.get_deletion_preview(kit_id)
    if not preview:
        raise HTTPException(status_code=404, detail="Kit not found")
    return KitDeletePreview(**preview)


@router.delete(
    "/{kit_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=_ANALYST,
)
async def delete_kit(kit_id: uuid.UUID, db: DbSession) -> None:
    service = KitService(db)
    deleted = await service.delete_kit(kit_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Kit not found")


@router.get("/{kit_id}/indicators")
async def get_kit_indicators(
    kit_id: uuid.UUID, db: DbSession, pagination: Pagination
):
    from darla.services.indicator_service import IndicatorService

    service = IndicatorService(db)
    indicators, total = await service.list_indicators(
        offset=pagination.offset, limit=pagination.limit, kit_id=kit_id
    )
    return {"items": indicators, "total": total}


@router.get("/{kit_id}/actors")
async def get_kit_actors(kit_id: uuid.UUID, db: DbSession):
    """Get actors linked to this kit through its indicators."""
    from darla.services.indicator_service import IndicatorService

    service = IndicatorService(db)
    actors = await service.get_linked_actors_for_kit(kit_id)
    return [{"id": str(a.id), "name": a.name} for a in actors]


@router.get("/{kit_id}/similar", response_model=list[SimilarKit])
async def find_similar_kits(
    kit_id: uuid.UUID,
    db: DbSession,
    threshold: int = 100,
) -> list[SimilarKit]:
    service = KitService(db)
    return await service.find_similar(kit_id, threshold=threshold)


@router.get("/{kit_id}/content", response_model=KitContentResponse)
async def get_kit_content(kit_id: uuid.UUID, db: DbSession) -> KitContentResponse:
    service = KitService(db)
    files = await service.get_kit_content(kit_id)
    if files is None:
        raise HTTPException(status_code=404, detail="Kit not found")
    return KitContentResponse(kit_id=kit_id, files=files)


@router.get("/{kit_id}/screenshots", response_model=ScreenshotsResponse)
async def get_kit_screenshots(kit_id: uuid.UUID, db: DbSession) -> ScreenshotsResponse:
    service = KitService(db)
    screenshots = await service.get_kit_screenshots(kit_id)
    if screenshots is None:
        raise HTTPException(status_code=404, detail="Kit not found")
    return ScreenshotsResponse(screenshots=screenshots)


@router.get("/{kit_id}/network-log", response_model=NetworkLogResponse)
async def get_kit_network_log(kit_id: uuid.UUID, db: DbSession) -> NetworkLogResponse:
    service = KitService(db)
    result = await service.get_kit_network_log(kit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Kit not found")
    return NetworkLogResponse(**result)


@router.get("/{kit_id}/browser-resources", response_model=BrowserResourcesResponse)
async def get_kit_browser_resources(kit_id: uuid.UUID, db: DbSession) -> BrowserResourcesResponse:
    service = KitService(db)
    resources = await service.get_kit_browser_resources(kit_id)
    if resources is None:
        raise HTTPException(status_code=404, detail="Kit not found")
    return BrowserResourcesResponse(resources=resources)


@router.get("/{kit_id}/deobfuscation-preview", response_model=DeobfuscationPreviewResponse)
async def get_kit_deobfuscation_preview(
    kit_id: uuid.UUID, db: DbSession,
) -> DeobfuscationPreviewResponse:
    service = KitService(db)
    pairs = await service.get_kit_deobfuscation_preview(kit_id)
    if pairs is None:
        raise HTTPException(status_code=404, detail="Kit not found")
    return DeobfuscationPreviewResponse(pairs=pairs)


@router.post(
    "/{kit_id}/reanalyze",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def reanalyze_kit(kit_id: uuid.UUID, db: DbSession):
    service = KitService(db)
    try:
        task_id = await service.reanalyze(kit_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Kit not found") from exc
    return {"kit_id": str(kit_id), "task_id": task_id}


@router.post("/{kit_id}/add-to-campaign", dependencies=_ANALYST)
async def add_kit_to_campaign(
    kit_id: uuid.UUID,
    payload: dict,
    db: DbSession,
):
    """Add a kit to a campaign.

    If the kit is a child in an investigation chain, the root kit is
    added instead so the full chain stays together.  Returns which kit
    was actually linked.
    """

    campaign_id = payload.get("campaign_id")
    if not campaign_id:
        raise HTTPException(status_code=400, detail="campaign_id is required")

    service = KitService(db)
    kit = await service.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")

    # Resolve root kit of the chain
    actual_kit = kit
    used_root = False
    if kit.parent_kit_id:
        # Walk up to the root
        current = kit
        while current.parent_kit_id:
            parent = await service.get_kit(current.parent_kit_id)
            if not parent:
                break
            current = parent
        actual_kit = current
        used_root = actual_kit.id != kit.id

    from darla.services.campaign_service import CampaignService

    campaign_svc = CampaignService(db)
    try:
        count = await campaign_svc.add_kits(
            uuid.UUID(campaign_id), [actual_kit.id]
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Campaign not found") from exc

    return {
        "added": count,
        "kit_id": str(actual_kit.id),
        "used_root": used_root,
        "message": f"Root kit {str(actual_kit.id)[:8]} added (child kit selected)"
        if used_root
        else "Kit added to campaign",
    }


@router.post("/{kit_id}/add-to-actor", dependencies=_ANALYST)
async def add_kit_to_actor(
    kit_id: uuid.UUID,
    payload: dict,
    db: DbSession,
):
    """Link a kit's indicators to an actor.

    If the kit is a child in an investigation chain, the root kit's
    indicators (and all children's indicators) are linked instead.
    """
    actor_id = payload.get("actor_id")
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id is required")

    service = KitService(db)
    kit = await service.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")

    # Resolve root kit of the chain
    actual_kit = kit
    used_root = False
    if kit.parent_kit_id:
        current = kit
        while current.parent_kit_id:
            parent = await service.get_kit(current.parent_kit_id)
            if not parent:
                break
            current = parent
        actual_kit = current
        used_root = actual_kit.id != kit.id

    # Gather indicators from root kit + all children
    from darla.services.indicator_service import IndicatorService

    indicator_service = IndicatorService(db)
    indicator_ids = await indicator_service.get_indicator_ids_for_kit_tree(
        actual_kit.id
    )

    if not indicator_ids:
        return {
            "linked": 0,
            "kit_id": str(actual_kit.id),
            "used_root": used_root,
            "message": "No indicators to link",
        }

    from darla.services.actor_service import ActorService

    actor_service = ActorService(db)
    actor = await actor_service.get_actor(uuid.UUID(actor_id))
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    count = await actor_service.link_indicators(
        uuid.UUID(actor_id), indicator_ids
    )

    return {
        "linked": count,
        "kit_id": str(actual_kit.id),
        "used_root": used_root,
        "message": f"Root kit {str(actual_kit.id)[:8]} indicators linked (child kit selected)"
        if used_root
        else f"{count} indicator(s) linked to actor",
    }


@router.post("/{kit_id}/add-to-family", dependencies=_ANALYST)
async def add_kit_to_family(
    kit_id: uuid.UUID,
    payload: dict,
    db: DbSession,
):
    """Link a kit to a family.

    If the kit is a child in an investigation chain, the root kit is
    added instead so the full chain stays together.
    """
    family_id = payload.get("family_id")
    if not family_id:
        raise HTTPException(status_code=400, detail="family_id is required")

    service = KitService(db)
    kit = await service.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="Kit not found")

    # Resolve root kit of the chain
    actual_kit = kit
    used_root = False
    if kit.parent_kit_id:
        current = kit
        while current.parent_kit_id:
            parent = await service.get_kit(current.parent_kit_id)
            if not parent:
                break
            current = parent
        actual_kit = current
        used_root = actual_kit.id != kit.id

    from darla.services.family_service import FamilyService

    family_svc = FamilyService(db)
    try:
        count = await family_svc.link_kits(
            uuid.UUID(family_id), [actual_kit.id]
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Family not found") from exc

    return {
        "added": count,
        "kit_id": str(actual_kit.id),
        "used_root": used_root,
        "message": f"Root kit {str(actual_kit.id)[:8]} added (child kit selected)"
        if used_root
        else "Kit added to family",
    }
