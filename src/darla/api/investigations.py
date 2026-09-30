"""Investigation API endpoints."""

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, status

from darla.api.deps import DbSession, Pagination
from darla.auth import require_role
from darla.config import get_settings
from darla.models import UserRole
from darla.schemas.investigation import (
    InvestigationCreate,
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationSubmitResponse,
    InvestigationSummary,
    InvestigationTreeNode,
    InvestigationUpdate,
)
from darla.schemas.kit import KitSummary
from darla.schemas.stage import (
    FlowDiffPair,
    FlowDiffResponse,
    FlowKitNode,
    FlowStageNode,
)
from darla.services.investigation_service import InvestigationService

router = APIRouter()

# See darla.api.actors for rationale on the shorthand.
_ANALYST = [Depends(require_role(UserRole.ANALYST))]


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    db: DbSession,
    pagination: Pagination,
) -> InvestigationListResponse:
    service = InvestigationService(db)
    investigations, total = await service.list_investigations(
        offset=pagination.offset, limit=pagination.limit,
    )
    return InvestigationListResponse(
        items=[InvestigationSummary.model_validate(i) for i in investigations],
        total=total,
    )


@router.post(
    "",
    response_model=InvestigationSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def create_investigation(
    payload: InvestigationCreate,
    db: DbSession,
) -> InvestigationSubmitResponse:
    """Create an investigation from a URL to crawl."""
    if not payload.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required",
        )

    from darla.api.kits import _link_kit_to_entities

    async def prepare(investigation, kit) -> None:
        # Override auto-generated name with user-provided name
        if payload.name:
            investigation.name = payload.name
            await db.flush()
        await _link_kit_to_entities(
            db, kit.id, payload.actor_id, payload.campaign_id, payload.family_id,
        )

    service = InvestigationService(db)
    investigation, kit, task_id = await service.create_from_url(
        str(payload.url), max_depth=payload.max_depth, prepare=prepare,
    )

    return InvestigationSubmitResponse(
        investigation_id=investigation.id,
        kit_id=kit.id,
        task_id=task_id,
    )


@router.post(
    "/upload",
    response_model=InvestigationSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=_ANALYST,
)
async def create_investigation_from_file(
    db: DbSession,
    file: UploadFile,
    name: str = Form(...),
    max_depth: int = Form(5),
    actor_id: str | None = Form(None),
    campaign_id: str | None = Form(None),
    family_id: str | None = Form(None),
) -> InvestigationSubmitResponse:
    """Create an investigation from an uploaded file."""
    settings = get_settings()
    max_bytes = settings.max_kit_size_mb * 1024 * 1024

    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_kit_size_mb}MB limit",
        )

    # Save file to disk
    kit_id = uuid.uuid4()
    download_dir = Path(settings.kit_download_dir) / str(kit_id)
    download_dir.mkdir(parents=True, exist_ok=True)
    filepath = download_dir / (file.filename or "upload.bin")
    filepath.write_bytes(content)

    from darla.api.kits import _link_kit_to_entities
    from darla.services.kit_service import KitService

    service = InvestigationService(db)
    investigation = None

    async def prepare(kit) -> None:
        # Investigation + links must be committed before the chain is
        # dispatched — see KitService's PrepareKit.
        nonlocal investigation
        investigation = await service.create_from_file(kit, max_depth=max_depth)
        investigation.name = name
        await db.flush()
        await _link_kit_to_entities(
            db, kit.id,
            uuid.UUID(actor_id) if actor_id else None,
            uuid.UUID(campaign_id) if campaign_id else None,
            uuid.UUID(family_id) if family_id else None,
        )

    kit_service = KitService(db)
    kit, task_id = await kit_service.submit_file(
        filename=file.filename or "upload.bin",
        local_path=str(filepath),
        source_feed="manual",
        kit_id=kit_id,
        prepare=prepare,
    )

    return InvestigationSubmitResponse(
        investigation_id=investigation.id,
        kit_id=kit.id,
        task_id=task_id or "",
    )


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: uuid.UUID,
    db: DbSession,
) -> InvestigationDetail:
    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    detail = InvestigationDetail.model_validate(investigation)
    if investigation.root_kit:
        detail.root_kit = KitSummary.model_validate(investigation.root_kit)
    return detail


@router.put("/{investigation_id}", response_model=InvestigationDetail, dependencies=_ANALYST)
async def update_investigation(
    investigation_id: uuid.UUID, payload: InvestigationUpdate, db: DbSession
) -> InvestigationDetail:
    service = InvestigationService(db)
    investigation = await service.update_investigation(
        investigation_id, payload.model_dump(exclude_unset=True)
    )
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    detail = InvestigationDetail.model_validate(investigation)
    if investigation.root_kit:
        detail.root_kit = KitSummary.model_validate(investigation.root_kit)
    return detail


@router.delete(
    "/{investigation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=_ANALYST,
)
async def delete_investigation(investigation_id: uuid.UUID, db: DbSession) -> None:
    service = InvestigationService(db)
    deleted = await service.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.commit()


@router.post("/bulk-delete", dependencies=_ANALYST)
async def bulk_delete_investigations(
    payload: dict,
    db: DbSession,
):
    """Delete multiple investigations by ID."""
    ids = payload.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="No IDs provided")

    service = InvestigationService(db)
    deleted = 0
    for raw_id in ids:
        try:
            inv_id = uuid.UUID(str(raw_id))
        except ValueError:
            continue
        if await service.delete_investigation(inv_id):
            deleted += 1
    await db.commit()
    return {"deleted": deleted}


@router.get("/{investigation_id}/tree", response_model=list[InvestigationTreeNode])
async def get_investigation_tree(
    investigation_id: uuid.UUID,
    db: DbSession,
) -> list[InvestigationTreeNode]:
    """Get the parent-child kit tree for an investigation."""
    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    kits = await service.get_kit_tree(investigation_id)
    return await _build_tree(kits)


@router.get("/{investigation_id}/kits")
async def get_investigation_kits(
    investigation_id: uuid.UUID,
    db: DbSession,
    pagination: Pagination,
):
    """Flat list of all kits in an investigation."""
    service = InvestigationService(db)
    kits = await service.get_kit_tree(investigation_id)
    total = len(kits)
    page = kits[pagination.offset:pagination.offset + pagination.limit]
    return {
        "items": [KitSummary.model_validate(k) for k in page],
        "total": total,
    }


@router.get("/{investigation_id}/flow", response_model=list[FlowKitNode])
async def get_investigation_flow(
    investigation_id: uuid.UUID,
    db: DbSession,
) -> list[FlowKitNode]:
    """Parent→child kit tree, each kit carrying its ordered stages.

    This is the data behind the flow view: the tree structure preserves
    the attack's branch points (email → link vs QR vs attachment) while
    each node expands into the pages the victim was actually walked
    through (lure → bot check → interstitial → AiTM proxy).
    """
    from darla.services.stage_service import StageService

    service = InvestigationService(db)
    investigation = await service.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    kits = await service.get_kit_tree(investigation_id)
    stage_service = StageService(db)
    stages = await stage_service.stages_for_investigation(investigation_id)
    stages_by_kit: dict[uuid.UUID, list] = {}
    for st in stages:
        stages_by_kit.setdefault(st.kit_id, []).append(st)

    nodes: dict[uuid.UUID, FlowKitNode] = {}
    for kit in kits:
        kit_stages = sorted(stages_by_kit.get(kit.id, []), key=lambda s: s.seq)
        nodes[kit.id] = FlowKitNode(
            kit_id=kit.id,
            source_url=kit.source_url,
            discovery_method=kit.discovery_method,
            chain_depth=kit.chain_depth,
            status=kit.status.value if hasattr(kit.status, "value") else str(kit.status),
            stages=[
                FlowStageNode(
                    id=s.id, kit_id=s.kit_id, seq=s.seq, url=s.url, host=s.host,
                    role=s.role.value, nav_method=s.nav_method,
                    screenshot_path=s.screenshot_path, dwell_seconds=s.dwell_seconds,
                    aitm_baseline=s.aitm_baseline,
                    resource_count=len(s.stage_resources),
                )
                for s in kit_stages
            ],
        )

    roots: list[FlowKitNode] = []
    for kit in kits:
        node = nodes[kit.id]
        if kit.parent_kit_id and kit.parent_kit_id in nodes:
            nodes[kit.parent_kit_id].children.append(node)
        else:
            roots.append(node)
    return roots


@router.get(
    "/{investigation_id}/flow-diff/{other_id}",
    response_model=FlowDiffResponse,
)
async def flow_diff(
    investigation_id: uuid.UUID,
    other_id: uuid.UUID,
    db: DbSession,
) -> FlowDiffResponse:
    """Stage-by-stage diff of two investigations' attack flows.

    Aligns the two flows by stage role (sequence alignment, so a stage
    present in only one side shows as a gap) and reports a per-pair
    verdict: *bot check same, interstitial only in A, AiTM different
    backend*.  This is the "compare one investigation's flow to another"
    comparison the stage model exists to serve.
    """
    from darla.analysis.stage_compare import align_flows
    from darla.services.stage_service import StageService, stage_to_fingerprint

    service = InvestigationService(db)
    inv_a = await service.get_investigation(investigation_id)
    inv_b = await service.get_investigation(other_id)
    if not inv_a or not inv_b:
        raise HTTPException(status_code=404, detail="Investigation not found")

    stage_service = StageService(db)
    stages_a = await stage_service.stages_for_investigation(investigation_id)
    stages_b = await stage_service.stages_for_investigation(other_id)

    # Only stages that carry comparison weight, in flow order.
    fp_a = [stage_to_fingerprint(s) for s in stages_a]
    fp_b = [stage_to_fingerprint(s) for s in stages_b]

    pairs_raw = align_flows(fp_a, fp_b)
    pairs: list[FlowDiffPair] = []
    for p in pairs_raw:
        a_stage = stages_a[p.a_index] if p.a_index is not None else None
        b_stage = stages_b[p.b_index] if p.b_index is not None else None
        pairs.append(FlowDiffPair(
            kind=p.kind,
            role=p.role,
            a_stage_id=str(a_stage.id) if a_stage else None,
            b_stage_id=str(b_stage.id) if b_stage else None,
            a_host=a_stage.host if a_stage else None,
            b_host=b_stage.host if b_stage else None,
            comparison=p.comparison,
        ))
    return FlowDiffResponse(
        investigation_a=investigation_id,
        investigation_b=other_id,
        pairs=pairs,
    )


def _render_nav_path(kit) -> list[str] | None:
    """Ordered distinct hosts a browser_render navigated through.

    Read from the render's persisted ``requests.json`` (a sibling of the
    kit's ``page.html``): the document-request URLs, in order, reduced to
    consecutive-distinct hostnames.  Returns None when unavailable — best
    effort for the tree view, never fatal.  Only ≥2-hop paths are worth
    showing (a single hop is just the node's own URL).
    """
    if kit.discovery_method != "browser_render" or not kit.local_path:
        return None
    from urllib.parse import urlparse

    log_path = Path(kit.local_path).parent / "requests.json"
    try:
        if not log_path.is_file() or log_path.stat().st_size > 8_000_000:
            return None
        entries = json.loads(log_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None

    hosts: list[str] = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        if e.get("type") != "request" or e.get("resource_type") != "document":
            continue
        # Iframes are "document" requests too (an AiTM page's Me.htm
        # session-probe frame, say) but aren't hops the browser took.
        headers = e.get("headers") if isinstance(e.get("headers"), dict) else {}
        dest = next(
            (v for k, v in headers.items() if k.lower() == "sec-fetch-dest"), None,
        )
        if dest in ("iframe", "frame"):
            continue
        host = urlparse(e.get("url") or "").hostname
        if host and (not hosts or hosts[-1] != host):
            hosts.append(host)
    return hosts if len(hosts) >= 2 else None


async def _build_tree(kits: list) -> list[InvestigationTreeNode]:
    """Build a tree of InvestigationTreeNode from a flat list of kits.

    ``_render_nav_path`` reads and JSON-parses each render's network log
    from disk; doing that inline would block the event loop (a large log
    stalls every other request during a tree view).  The reads run off
    the loop in threads, concurrently across render kits.
    """
    import asyncio

    render_kits = [
        k for k in kits
        if k.discovery_method == "browser_render" and k.local_path
    ]
    nav_lists = await asyncio.gather(
        *(asyncio.to_thread(_render_nav_path, k) for k in render_kits)
    )
    nav_by_id = {k.id: nav for k, nav in zip(render_kits, nav_lists, strict=True)}

    nodes: dict[uuid.UUID, InvestigationTreeNode] = {}
    roots: list[InvestigationTreeNode] = []

    for kit in kits:
        node = InvestigationTreeNode(
            kit=KitSummary.model_validate(kit),
            discovery_method=kit.discovery_method,
            chain_depth=kit.chain_depth,
            nav_path=nav_by_id.get(kit.id),
        )
        nodes[kit.id] = node

    for kit in kits:
        node = nodes[kit.id]
        if kit.parent_kit_id and kit.parent_kit_id in nodes:
            nodes[kit.parent_kit_id].children.append(node)
        else:
            roots.append(node)

    return roots
