"""Stage persistence, fingerprinting, and cross-investigation queries.

Two halves:

* **Sync ingest** (:func:`build_and_store_stages`) — called from the
  browser render task (and the httpx download task for redirect chains).
  Segments a render into stages, content-addresses every sub-resource,
  computes each stage's fingerprint (baseline-subtracted for AiTM cred
  pages), and writes ``Stage`` / ``Resource`` / ``StageResource`` rows.

* **Async queries** — used by the API: per-kit flow, same-role similar
  stages, role clusters, and the bot-check × AiTM co-occurrence matrix.

The fingerprint math lives in :mod:`darla.analysis.stage_fingerprint` and
:mod:`darla.analysis.stage_compare`; this module is the glue to storage.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.analysis import stage_fingerprint as sf
from darla.analysis.staging import StageSpec, segment_render
from darla.models.resource import Resource, StageResource
from darla.models.stage import Stage, StageRole

logger = logging.getLogger(__name__)

_INLINE_SCRIPT_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_SCRIPT_INITIATORS = {"script_src", "dynamic", "inline"}

# Baseline script/endpoint sets for known IdPs, learned lazily from the
# first genuine login page we see.  Empty until populated; subtraction
# then simply keeps everything (no worse than not subtracting).  A future
# improvement seeds these from a reference render — kept as a module-level
# cache so it survives within a worker process.
_IDP_BASELINES: dict[str, dict[str, set[str]]] = {}


# ---------------------------------------------------------------------------
# Pure fingerprint assembly (testable without a DB)
# ---------------------------------------------------------------------------

def fingerprint_from_parts(
    *,
    role: str,
    url: str,
    body_text: str,
    is_final: bool,
    script_shas: set[str],
    endpoints: set[str],
    screenshot_path: str | None,
) -> dict:
    """Assemble the stored fingerprint dict + indexed-column values.

    Returns a dict with the indexed columns (``tlsh_raw`` …) alongside a
    ``fingerprint`` sub-dict of the richer, non-indexed material.
    """
    tlsh_raw = sf.tlsh_of_text(body_text) if body_text else None
    tlsh_rendered = sf.rendered_tlsh(body_text) if (is_final and body_text) else None
    skel = sf.skeleton_hash(body_text) if body_text else None
    phash = sf.screenshot_phash(screenshot_path) if screenshot_path else None

    idp = sf.detect_idp_baseline(body_text, url) if role == "cred_capture" else None
    injected: dict = {}
    if idp:
        baseline = _IDP_BASELINES.get(idp, {})
        injected = sf.injected_fingerprint(
            stage_script_shas=script_shas,
            baseline_script_shas=baseline.get("scripts", set()),
            stage_endpoints=endpoints,
            baseline_endpoints=baseline.get("endpoints", set()),
        )

    fingerprint = {
        "role": role,
        "script_shas": sorted(script_shas),
        "endpoints": sorted(endpoints),
        "idp_baseline": idp,
    }
    if injected:
        fingerprint["injected_scripts"] = injected["injected_scripts"]
        fingerprint["injected_endpoints"] = injected["injected_endpoints"]
        fingerprint["injected_hash"] = injected["injected_hash"]

    return {
        "tlsh_raw": tlsh_raw,
        "tlsh_rendered": tlsh_rendered,
        "skeleton_hash": skel,
        "screenshot_phash": phash,
        "tlsh_bucket": sf.tlsh_bucket(tlsh_rendered or tlsh_raw),
        "aitm_baseline": idp,
        "fingerprint": fingerprint,
    }


def stage_to_fingerprint(stage: Stage) -> dict:
    """Flatten a Stage row into the dict shape ``stage_compare`` expects."""
    fp = dict(stage.fingerprint or {})
    fp.update({
        "id": str(stage.id),
        "role": stage.role.value if hasattr(stage.role, "value") else stage.role,
        "tlsh_raw": stage.tlsh_raw,
        "tlsh_rendered": stage.tlsh_rendered,
        "skeleton_hash": stage.skeleton_hash,
        "request_shape_hash": stage.request_shape_hash,
        "screenshot_phash": stage.screenshot_phash,
    })
    return fp


# ---------------------------------------------------------------------------
# Sync ingest
# ---------------------------------------------------------------------------

def _get_or_create_resource(
    db, sha256: str, *, tlsh: str | None, size: int, content_type: str | None,
    path: str | None, meta: dict,
) -> Resource:
    existing = db.query(Resource).filter(Resource.sha256 == sha256).first()
    if existing is not None:
        return existing
    res = Resource(
        id=uuid.uuid4(), sha256=sha256, tlsh=tlsh, size=size,
        content_type=content_type, path=path, meta=meta,
    )
    db.add(res)
    db.flush()
    return res


def build_and_store_stages(db, kit, dest_dir: str | Path) -> int:
    """Segment a render dir, fingerprint each stage, and persist rows.

    Idempotent: existing stages for ``kit`` are deleted and rebuilt so a
    reanalysis re-render produces one clean set.  Returns the number of
    stages written.  All IO is best-effort — a malformed manifest yields
    zero stages rather than raising into the Celery chain.
    """
    dest = Path(dest_dir)
    try:
        specs = segment_render(dest)
    except Exception as e:
        logger.debug("segment_render failed for kit %s: %s", kit.id, e)
        return 0
    if not specs:
        return 0

    # Clear any prior stages for this kit (reanalysis).
    db.query(Stage).filter(Stage.kit_id == kit.id).delete(
        synchronize_session=False,
    )

    written = 0
    last_idx = len(specs) - 1
    for idx, spec in enumerate(specs):
        try:
            _store_one_stage(db, kit, dest, spec, is_final=idx == last_idx)
            written += 1
        except Exception as e:
            logger.debug("Failed to store stage seq=%s: %s", spec.seq, e)
    db.flush()
    logger.info("Kit %s: stored %d stages", kit.id, written)
    return written


def _read_text(dest: Path, rel: str | None) -> str:
    if not rel:
        return ""
    p = dest / rel
    try:
        if p.is_file() and p.stat().st_size < 8_000_000:
            return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""


def _store_one_stage(db, kit, dest: Path, spec: StageSpec, *, is_final: bool) -> None:
    body_text = _read_text(dest, spec.body_path)
    role = spec.role.value if hasattr(spec.role, "value") else str(spec.role)

    # --- Resource rows for this stage's sub-resources ---
    script_shas: set[str] = set()
    endpoints: set[str] = set()
    script_bodies_text = ""
    stage_resource_specs: list[tuple[Resource, dict]] = []

    for r in spec.resources:
        rel = r.get("path")
        data: bytes | None = None
        p = dest / rel if rel else None
        try:
            if p and p.is_file() and p.stat().st_size < 4_000_000:
                data = p.read_bytes()
        except OSError:
            data = None
        if data is None:
            continue
        sha = hashlib.sha256(data).hexdigest()
        res = _get_or_create_resource(
            db, sha,
            tlsh=sf.tlsh_of_text(data.decode("utf-8", errors="replace")),
            size=len(data),
            content_type=r.get("content_type"),
            path=rel,
            meta={"initiator": r.get("initiator")},
        )
        stage_resource_specs.append((res, r))
        initiator = r.get("initiator")
        if initiator in _SCRIPT_INITIATORS:
            script_shas.add(sha)
            script_bodies_text += "\n" + data.decode("utf-8", errors="replace")
        if initiator in ("xhr", "fetch"):
            endpoints.add(sf.path_template(r.get("url") or ""))

    # --- Inline scripts extracted from the body → resources too ---
    for m in _INLINE_SCRIPT_RE.finditer(body_text or ""):
        code = m.group(1).strip()
        if len(code) < 16:
            continue
        data = code.encode("utf-8", errors="replace")
        sha = hashlib.sha256(data).hexdigest()
        res = _get_or_create_resource(
            db, sha, tlsh=sf.tlsh_of_text(code), size=len(data),
            content_type="application/javascript", path=None,
            meta={"initiator": "inline"},
        )
        stage_resource_specs.append((res, {
            "url": spec.url, "initiator": "inline",
            "doc_seq": spec.seq, "ts": None,
        }))
        script_shas.add(sha)
        script_bodies_text += "\n" + code

    endpoints |= sf.extract_endpoints([], extra_text=body_text + script_bodies_text)

    # Request-shape hash from resource URLs of this stage (+ ws).
    pseudo_log = [
        {"type": "request", "method": "GET",
         "resource_type": _rtype(r.get("initiator")), "url": r.get("url")}
        for r in spec.resources
    ]
    request_shape_hash = sf.request_shape_hash(pseudo_log)

    fp = fingerprint_from_parts(
        role=role, url=spec.url or "", body_text=body_text, is_final=is_final,
        script_shas=script_shas, endpoints=endpoints,
        screenshot_path=str(dest / spec.screenshot_path) if spec.screenshot_path else None,
    )

    stage = Stage(
        id=uuid.uuid4(),
        kit_id=kit.id,
        seq=spec.seq,
        url=spec.url,
        host=spec.host,
        role=StageRole(role) if role in StageRole._value2member_map_ else StageRole.UNKNOWN,
        nav_method=spec.nav_method,
        body_path=spec.body_path,
        screenshot_path=spec.screenshot_path,
        status_code=spec.status_code,
        content_type=spec.content_type,
        dwell_seconds=spec.dwell_seconds,
        tlsh_raw=fp["tlsh_raw"],
        tlsh_rendered=fp["tlsh_rendered"],
        skeleton_hash=fp["skeleton_hash"],
        request_shape_hash=request_shape_hash,
        screenshot_phash=fp["screenshot_phash"],
        aitm_baseline=fp["aitm_baseline"],
        tlsh_bucket=fp["tlsh_bucket"],
        fingerprint=fp["fingerprint"],
    )
    db.add(stage)
    db.flush()

    for res, r in stage_resource_specs:
        db.add(StageResource(
            id=uuid.uuid4(),
            stage_id=stage.id,
            resource_id=res.id,
            url=r.get("url"),
            initiator=r.get("initiator"),
            doc_seq=r.get("doc_seq"),
            ts=r.get("ts"),
        ))


def _rtype(initiator: str | None) -> str:
    return {
        "script_src": "script", "dynamic": "script", "css": "stylesheet",
        "fetch": "fetch", "xhr": "xhr", "iframe": "document",
    }.get(initiator or "", "other")


# ---------------------------------------------------------------------------
# Async queries
# ---------------------------------------------------------------------------

class StageService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def stages_for_kit(self, kit_id: uuid.UUID) -> list[Stage]:
        res = await self.db.execute(
            select(Stage)
            .where(Stage.kit_id == kit_id)
            .options(selectinload(Stage.stage_resources))
            .order_by(Stage.seq)
        )
        return list(res.scalars().all())

    async def get_stage(self, stage_id: uuid.UUID) -> Stage | None:
        res = await self.db.execute(
            select(Stage)
            .where(Stage.id == stage_id)
            .options(
                selectinload(Stage.stage_resources).selectinload(
                    StageResource.resource
                )
            )
        )
        return res.scalar_one_or_none()

    async def stages_for_investigation(
        self, investigation_id: uuid.UUID,
    ) -> list[Stage]:
        from darla.models.kit import Kit

        res = await self.db.execute(
            select(Stage)
            .join(Kit, Stage.kit_id == Kit.id)
            .where(Kit.investigation_id == investigation_id)
            .options(selectinload(Stage.stage_resources))
            .order_by(Kit.chain_depth, Stage.seq)
        )
        return list(res.scalars().all())

    async def find_similar_stages(
        self, stage: Stage, limit: int = 50,
    ) -> list[dict]:
        """Same-role stages ranked by :func:`compare_stages`.

        Candidate set is pre-filtered to the same role (indexed) and, when
        a TLSH bucket exists, that bucket — so this does not full-scan the
        stages table.  Returns dicts with the matched stage + comparison.
        """
        from darla.analysis.stage_compare import compare_stages

        conds = [Stage.role == stage.role, Stage.id != stage.id]
        res = await self.db.execute(select(Stage).where(*conds))
        candidates = list(res.scalars().all())

        me = stage_to_fingerprint(stage)
        scored: list[dict] = []
        for c in candidates:
            cmp = compare_stages(me, stage_to_fingerprint(c), stage.role.value)
            if cmp.score <= 0.0:
                continue
            scored.append({
                "stage_id": str(c.id),
                "kit_id": str(c.kit_id),
                "url": c.url,
                "host": c.host,
                "role": c.role.value,
                "score": round(cmp.score, 3),
                "verdict": cmp.verdict,
                "comparison": cmp.to_dict(),
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:limit]

    async def cluster_role(self, role: StageRole) -> list[dict]:
        """Cluster all stages of ``role`` into families (largest first)."""
        from darla.analysis.stage_compare import cluster_stages

        res = await self.db.execute(select(Stage).where(Stage.role == role))
        stages = list(res.scalars().all())
        by_id = {str(s.id): s for s in stages}
        fps = [stage_to_fingerprint(s) for s in stages]
        clusters = cluster_stages(fps, role=role.value)
        out: list[dict] = []
        for idx, ids in enumerate(clusters):
            members = [by_id[i] for i in ids if i in by_id]
            hosts = sorted({m.host for m in members if m.host})
            out.append({
                "cluster_id": f"{role.value}:{idx}",
                "role": role.value,
                "size": len(ids),
                "stage_ids": ids,
                "hosts": hosts,
            })
        return out

    async def cooccurrence(
        self, role_a: StageRole, role_b: StageRole,
    ) -> dict:
        """Matrix of how often each ``role_a`` cluster pairs with each
        ``role_b`` cluster across investigations.

        Surfaces PhaaS mix-and-match: an operator renting a bot check from
        one provider and an AiTM proxy from another shows up as one
        bot-check cluster spanning several AiTM clusters (or vice versa).
        """
        from darla.models.kit import Kit

        clusters_a = await self.cluster_role(role_a)
        clusters_b = await self.cluster_role(role_b)
        stage_to_cluster_a = {
            sid: c["cluster_id"] for c in clusters_a for sid in c["stage_ids"]
        }
        stage_to_cluster_b = {
            sid: c["cluster_id"] for c in clusters_b for sid in c["stage_ids"]
        }

        # Map each stage to its investigation.
        res = await self.db.execute(
            select(Stage.id, Kit.investigation_id)
            .join(Kit, Stage.kit_id == Kit.id)
            .where(Stage.role.in_([role_a, role_b]))
        )
        inv_of: dict[str, list[str]] = {}
        for stage_id, inv_id in res.all():
            if inv_id is None:
                continue
            inv_of.setdefault(str(inv_id), []).append(str(stage_id))

        # For each investigation, the set of a-clusters and b-clusters present.
        matrix: dict[str, dict[str, int]] = {}
        for _inv, stage_ids in inv_of.items():
            a_clusters = {
                stage_to_cluster_a[s] for s in stage_ids if s in stage_to_cluster_a
            }
            b_clusters = {
                stage_to_cluster_b[s] for s in stage_ids if s in stage_to_cluster_b
            }
            for ca in a_clusters:
                for cb in b_clusters:
                    matrix.setdefault(ca, {}).setdefault(cb, 0)
                    matrix[ca][cb] += 1

        return {
            "role_a": role_a.value,
            "role_b": role_b.value,
            "clusters_a": clusters_a,
            "clusters_b": clusters_b,
            "matrix": matrix,
        }
