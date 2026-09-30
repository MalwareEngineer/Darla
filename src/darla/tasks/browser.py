"""Browser-based download Celery task for Cloudflare-protected pages.

Runs on the dedicated ``browser`` queue consumed by worker-browser (solo pool).
Creates a **child kit** linked to the original httpx-downloaded parent, so both
the raw JS loader and the browser-rendered credential form are preserved as
separate entities with a parent→child relationship.

Dedup strategy:
  1. **Ancestor chain** — compare child against its parent chain (parent,
     grandparent, …, root).  A match means the kit is stuck at a protection
     gate (e.g. Cloudflare Turnstile).  No re-render is scheduled.
  2. **Direct siblings** — compare child against other children of the same
     parent.  A match means the relay domain pool is repeating.  A re-render
     is scheduled with an incremented dupe counter.
  Both checks use TLSH distance with SHA256 fallback for tiny files.
  Neither check ever deletes kits — duplicates are marked FAILED with
  ``duplicate_of_kit_id`` set and files preserved on disk.
"""

import contextlib
import logging
import uuid
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func, or_

from darla.analysis.browser_downloader import browser_download
from darla.analysis.hasher import compute_hashes as do_hash
from darla.analysis.hasher import compute_tlsh_distance
from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pre-create helper for browser-render children
# ---------------------------------------------------------------------------

def precreate_browser_render_child_kit(
    db, parent_kit: Kit,
) -> tuple[Kit | None, str | None]:
    """Apply browser-render guards and create a child kit row.

    Caller must commit/rollback the transaction.  The child row is
    created in ``DOWNLOADING`` status and the investigation counters
    are incremented atomically — no orphan rows on guard failure.

    Returns ``(child_kit, None)`` on success, or ``(None, reason)``
    when one of the guards trips:

      * ``max_depth``       — beyond ``Investigation.max_depth`` /
                              ``settings.chain_max_depth``
      * ``max_variations``  — beyond ``browser_render_max_variations``
                              for this investigation
      * ``inflight_budget`` — already at
                              ``browser_render_max_inflight_per_investigation``
                              concurrent renders for this investigation

    The pre-create-then-pass-id flow exists so that Celery task
    redeliveries (after a worker SIGTERM, prefetch eviction, etc.)
    can be made idempotent: the redelivered task sees the child row
    already past ``DOWNLOADING`` and exits no-op instead of starting
    a duplicate render.
    """
    settings = get_settings()

    # Depth guard — refuse to create another child beyond max_depth
    if parent_kit.investigation_id:
        from darla.models.investigation import Investigation

        investigation = db.query(Investigation).filter(
            Investigation.id == parent_kit.investigation_id
        ).first()
        if investigation:
            max_depth = min(investigation.max_depth, settings.chain_max_depth)
            if parent_kit.chain_depth >= max_depth:
                return None, "max_depth"

    # Variation cap — limit total browser_render children per investigation
    if parent_kit.investigation_id:
        browser_child_count = db.query(func.count(Kit.id)).filter(
            Kit.investigation_id == parent_kit.investigation_id,
            Kit.discovery_method == "browser_render",
        ).scalar()
        if browser_child_count >= settings.browser_render_max_variations:
            return None, "max_variations"

    # In-flight budget — per-investigation cap on concurrent renders
    allowed, _ = _can_dispatch_browser_render(
        db,
        parent_kit.investigation_id,
        settings.browser_render_max_inflight_per_investigation,
    )
    if not allowed:
        return None, "inflight_budget"

    child_kit = Kit(
        source_url=parent_kit.source_url,
        source_feed=parent_kit.source_feed,
        status=KitStatus.DOWNLOADING,
        parent_kit_id=parent_kit.id,
        investigation_id=parent_kit.investigation_id,
        chain_depth=parent_kit.chain_depth + 1,
        discovery_method="browser_render",
    )
    db.add(child_kit)
    db.flush()  # populate child_kit.id

    if parent_kit.investigation_id:
        from darla.models.investigation import Investigation

        investigation = db.query(Investigation).filter(
            Investigation.id == parent_kit.investigation_id
        ).first()
        if investigation:
            investigation.total_kits += 1
            new_depth = parent_kit.chain_depth + 1
            if new_depth > investigation.total_depth_reached:
                investigation.total_depth_reached = new_depth

    return child_kit, None


# ---------------------------------------------------------------------------
# Dispatch throttle — per-investigation in-flight budget
# ---------------------------------------------------------------------------

def _can_dispatch_browser_render(
    db, investigation_id, max_inflight: int,
) -> tuple[bool, int]:
    """Return ``(allowed, current_inflight)`` for a new browser_render
    dispatch on this investigation.

    "In-flight" means a child kit with ``discovery_method='browser_render'``
    in ``DOWNLOADING`` status — it's currently being rendered by some
    worker.  Tasks that have completed (ANALYZED) or failed are NOT
    counted; only actively-occupying-a-worker work counts toward the
    budget.

    With a single Camoufox worker handling the whole queue, an
    adversarial AITM with relay rotation can dispatch up to
    ``browser_render_max_variations`` (now 10) renders in succession,
    starving any other investigation hitting the same worker.  This
    cap means no single investigation can hold more than
    ``max_inflight`` browser tasks at once; the rest queue locally on
    the parent's chain and wait for slots to free up.

    When ``investigation_id`` is None (pre-investigation root kit) the
    check is a no-op — root kits are by definition the first dispatch
    in their chain so the budget can't be busy yet.
    """
    if investigation_id is None:
        return True, 0
    inflight = (
        db.query(func.count(Kit.id))
        .filter(
            Kit.investigation_id == investigation_id,
            Kit.discovery_method == "browser_render",
            Kit.status == KitStatus.DOWNLOADING,
        )
        .scalar()
    ) or 0
    return inflight < max_inflight, inflight


# ---------------------------------------------------------------------------
# Dedup helpers
# ---------------------------------------------------------------------------

# SHA256 of the empty byte string — every 0-byte download shares it, so
# it is never a meaningful dedup signal.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def find_sha256_match(
    db, sha256: str, exclude_kit_id, investigation_id,
) -> Kit | None:
    """Return another kit with *sha256*, preferring the same investigation.

    Callers treat a same-investigation match as redundancy (mark FAILED)
    and a cross-investigation match as a correlation signal (keep
    analyzing).  An unordered ``.first()`` over all investigations can
    surface the cross-investigation row even when a same-investigation
    duplicate exists, silently downgrading redundancy to correlation —
    so look in the kit's own investigation first.
    """
    same = db.query(Kit).filter(
        Kit.sha256 == sha256,
        Kit.id != exclude_kit_id,
        Kit.investigation_id == investigation_id,
    ).first()
    if same is not None:
        return same
    return db.query(Kit).filter(
        Kit.sha256 == sha256,
        Kit.id != exclude_kit_id,
    ).first()


def find_redundant_render_reason(db, kit: Kit, sha256: str | None) -> str | None:
    """Return why a pre-analysis browser render of *kit* is redundant.

    ``download_kit`` dispatches Tier A renders (JS loader, embedded
    Turnstile, OAuth handoff) *before* ``compute_hashes`` gets a chance
    to dedup the kit.  Once queued, a render can't be recalled: it burns
    a 60-150s browser slot and — when the page carries per-request
    nonces so the rendered bytes differ — spawns a whole duplicate
    subtree.  Returns ``None`` when the render should proceed.

    Two cases are provably redundant:
      1. **Same-investigation SHA256 duplicate.**  ``compute_hashes``
         will mark this kit FAILED; rendering it is wasted work.
      2. **Redirect child of an already-rendered parent.**  The parent's
         browser render started at the parent URL and followed the same
         redirect to this kit's URL (the mirror of ``crawl_chain``
         skipping browser_render kits).  Error-FAILED parent renders
         don't count — the child gets its own attempt.  Renders FAILED
         as duplicates *do* count: the browser reached the page fine.

    Only investigation kits are checked; feed kits keep existing behavior.
    """
    if kit.investigation_id is None:
        return None

    if sha256 and sha256 != EMPTY_SHA256:
        dup = db.query(Kit).filter(
            Kit.investigation_id == kit.investigation_id,
            Kit.sha256 == sha256,
            Kit.id != kit.id,
        ).first()
        if dup is not None:
            return f"same-investigation SHA256 duplicate of kit {dup.id}"

    if kit.discovery_method == "redirect" and kit.parent_kit_id:
        render = db.query(Kit).filter(
            Kit.parent_kit_id == kit.parent_kit_id,
            Kit.discovery_method == "browser_render",
            or_(
                Kit.status != KitStatus.FAILED,
                Kit.duplicate_of_kit_id.isnot(None),
            ),
        ).first()
        if render is not None:
            return (
                f"parent's browser render {render.id} already followed "
                f"this redirect"
            )

    return None


def _known_landing_hosts(db, kit: Kit) -> set[str]:
    """Hosts *kit* is known to land on without any relay rotation: its own
    host plus every host on its recorded HTTP redirect chain."""
    from darla.models.analysis_result import AnalysisResult, AnalysisType

    hosts = {urlparse(kit.source_url).hostname}
    chain = db.query(AnalysisResult.result_data).filter(
        AnalysisResult.kit_id == kit.id,
        AnalysisResult.analysis_type == AnalysisType.REDIRECT_CHAIN,
    ).scalar()
    if chain:
        urls = [chain.get("final_url")]
        for hop in chain.get("hops") or []:
            urls += [hop.get("url"), hop.get("location")]
        hosts |= {urlparse(u).hostname for u in urls if u}
    hosts.discard(None)
    return hosts


def _complete_investigation_if_done(db, kit: Kit) -> None:
    """Run the investigation-completion check for a render that ended as a
    duplicate.  Those never reach ``finalize_kit``, so when one is the last
    kit to finish, the investigation otherwise sits IN_PROGRESS until the
    hourly recovery sweep."""
    if kit.investigation_id:
        from darla.tasks.analysis import _try_complete_investigation

        _try_complete_investigation(db, kit.investigation_id)


def _walk_ancestor_chain(db, kit: Kit, max_depth: int = 5) -> list[Kit]:
    """Walk ``parent_kit_id`` links up to root.

    Returns ``[parent, grandparent, …]``.  Bounded by *max_depth* to
    prevent runaway loops.  Uses the indexed ``parent_kit_id`` FK so
    each hop is a single-row PK lookup.
    """
    ancestors: list[Kit] = []
    current = kit
    for _ in range(max_depth):
        if not current.parent_kit_id:
            break
        parent = db.query(Kit).filter(Kit.id == current.parent_kit_id).first()
        if not parent:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


def _get_direct_siblings(db, kit: Kit) -> list[Kit]:
    """Return browser-render children sharing the same parent (excluding *kit*)."""
    if not kit.parent_kit_id:
        return []
    return db.query(Kit).filter(
        Kit.parent_kit_id == kit.parent_kit_id,
        Kit.id != kit.id,
        Kit.discovery_method == "browser_render",
    ).all()


def _content_matches(
    child_tlsh: str | None,
    child_sha256: str | None,
    other_tlsh: str | None,
    other_sha256: str | None,
    threshold: int,
) -> tuple[bool, str]:
    """Compare two kits' content.  Returns ``(is_match, detail_string)``.

    Uses TLSH distance when both hashes are available, falls back to exact
    SHA256 for tiny files where TLSH is None.
    """
    if child_tlsh and other_tlsh:
        distance = compute_tlsh_distance(child_tlsh, other_tlsh)
        if distance is not None and distance <= threshold:
            return True, f"TLSH distance {distance} (threshold {threshold})"
    if child_sha256 and other_sha256 and child_sha256 == other_sha256:
        return True, "exact SHA256 match"
    return False, ""


def _find_ancestor_match(
    child_kit: Kit,
    ancestors: list[Kit],
    threshold: int,
) -> tuple[Kit | None, str]:
    """Check whether *child_kit* is stuck at the same gate as an ancestor.

    Returns ``(matched_ancestor, reason)`` or ``(None, "")``.

    Two signals count as a stuck-at-gate match:
      1. **Rendered-URL equality vs a browser_render ancestor.**  If we
         just browser-rendered the exact URL a browser_render ancestor
         also rendered, we are looping on the same gate.  Content-hash
         comparison misses this because cloaking gates (Cloudflare
         Turnstile, hCaptcha) inject per-session nonces so every render
         is byte-different even though semantically identical.  We only
         apply this check against ``browser_render`` ancestors so the
         *first* browser render of an httpx parent is not falsely
         suppressed (child.source_url typically equals parent.source_url
         on a first render with no redirect).
      2. **Content similarity** — TLSH distance below *threshold* or an
         exact SHA256 match (fallback for tiny files).
    """
    for ancestor in ancestors:
        if (
            ancestor.discovery_method == "browser_render"
            and child_kit.source_url
            and ancestor.source_url
            and child_kit.source_url == ancestor.source_url
        ):
            return ancestor, (
                f"Same rendered URL as ancestor {ancestor.id} at depth "
                f"{ancestor.chain_depth} — stuck at gate"
            )
        matched, detail = _content_matches(
            child_kit.tlsh, child_kit.sha256,
            ancestor.tlsh, ancestor.sha256,
            threshold,
        )
        if matched:
            return ancestor, (
                f"Content matches ancestor {ancestor.id} at depth "
                f"{ancestor.chain_depth} ({detail}) — stuck at gate"
            )
    return None, ""


@celery_app.task(
    name="darla.tasks.browser.browser_download_kit",
    bind=True,
    max_retries=0,
    # Override the worker-level ``task_acks_late=True`` for this task.
    # Browser renders are long (60-150s) and not safely retriable —
    # if the worker dies, redelivery would create a duplicate child
    # kit (the original is still mid-render or already FAILED).  Ack
    # immediately on receipt; the recovery beat job will pick up
    # stuck DOWNLOADING child kits.
    acks_late=False,
    queue="browser",
)
def browser_download_kit(
    self,
    kit_id: str,
    child_kit_id: str | None = None,
    consecutive_dupes: int = 0,
) -> dict:
    """Download a kit using the Camoufox stealth browser.

    Called by ``download_kit`` (and self-redispatched for relay-pool
    enumeration).  Creates a child kit linked to the httpx-downloaded
    parent and dispatches the post-download analysis chain for it.

    ``child_kit_id`` is the **idempotency handle**.  Modern callers
    pre-create the child kit via :func:`precreate_browser_render_child_kit`
    in their own transaction and pass the resulting id here.  On task
    redelivery (worker SIGTERM, broker reconnect, etc.) the redelivered
    instance sees the child already past ``DOWNLOADING`` and exits
    no-op — preventing the duplicate-child orphans we used to get on
    every worker rebuild.  When ``None`` (legacy callers / direct
    operator invocations), the task pre-creates the child itself for
    backward compatibility.

    Stops the relay-pool enumeration loop after
    ``browser_render_pool_stop`` consecutive TLSH duplicates (pool
    exhausted) or when ``browser_render_max_variations`` is reached.
    """
    settings = get_settings()
    db = get_sync_db()

    try:
        parent_kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not parent_kit:
            raise ValueError(f"Kit {kit_id} not found")

        # Pool exhaustion — N consecutive renders matched existing siblings
        if consecutive_dupes >= settings.browser_render_pool_stop:
            logger.info(
                "Kit %s: relay pool exhausted (%d consecutive dupes, threshold %d)",
                kit_id, consecutive_dupes, settings.browser_render_pool_stop,
            )
            return {
                "kit_id": kit_id,
                "status": "pool_exhausted",
                "consecutive_dupes": consecutive_dupes,
            }

        # ------------------------------------------------------------------
        # Idempotency: resolve or create the child kit.
        # ------------------------------------------------------------------
        if child_kit_id is not None:
            child_kit = db.query(Kit).filter(
                Kit.id == uuid.UUID(child_kit_id)
            ).first()
            if child_kit is None:
                logger.warning(
                    "Kit %s: pre-created child %s vanished — exiting",
                    kit_id, child_kit_id,
                )
                return {
                    "kit_id": kit_id,
                    "child_kit_id": child_kit_id,
                    "status": "missing_child",
                }
            if child_kit.parent_kit_id != parent_kit.id:
                logger.error(
                    "Kit %s: child %s has parent %s, not %s — refusing to render",
                    kit_id, child_kit_id, child_kit.parent_kit_id, parent_kit.id,
                )
                return {
                    "kit_id": kit_id,
                    "child_kit_id": child_kit_id,
                    "status": "child_parent_mismatch",
                }
            if child_kit.status != KitStatus.DOWNLOADING:
                # Redelivery — a previous execution of this task already
                # completed and moved the child past DOWNLOADING.  Exit
                # cleanly so we don't double-render.
                logger.info(
                    "Kit %s: child %s already %s — task redelivery, exiting",
                    kit_id, child_kit_id, child_kit.status,
                )
                return {
                    "kit_id": kit_id,
                    "child_kit_id": child_kit_id,
                    "status": "already_handled",
                    "child_status": str(child_kit.status),
                }
        else:
            # Legacy / direct invocation — pre-create the child here.
            child_kit, skip_reason = precreate_browser_render_child_kit(
                db, parent_kit,
            )
            if child_kit is None:
                logger.info(
                    "Kit %s: skipping browser render (%s)",
                    kit_id, skip_reason,
                )
                return {
                    "kit_id": kit_id,
                    "status": "skipped",
                    "reason": skip_reason,
                }

        child_id = str(child_kit.id)

        logger.info(
            "Browser downloading kit %s (child %s) from %s",
            kit_id, child_id, parent_kit.source_url,
        )

        db.commit()

        # Download into child kit's own directory
        download_dir = Path(settings.kit_download_dir) / child_id
        download_dir.mkdir(parents=True, exist_ok=True)

        filepath, reason, final_url, interaction_driven = browser_download(
            parent_kit.source_url,
            str(download_dir),
            timeout=settings.browser_download_timeout,
            turnstile_timeout=settings.browser_turnstile_timeout,
        )

        if not filepath:
            child_kit.status = KitStatus.FAILED
            child_kit.error_message = f"Browser fallback failed: {reason}"
            # Mark parent as FAILED only if it hasn't already been analyzed
            # (re-renders may fail after first successful render)
            if parent_kit.status != KitStatus.ANALYZED:
                parent_kit.status = KitStatus.FAILED
                parent_kit.error_message = (
                    f"httpx: ConnectError → browser: {reason}"[:500]
                )
            db.commit()

            # Check investigation completion (both kits are now terminal)
            if parent_kit.investigation_id:
                from darla.tasks.analysis import _try_complete_investigation

                _try_complete_investigation(db, parent_kit.investigation_id)

            logger.warning(
                "Browser download failed for child kit %s (parent %s): %s",
                child_id, kit_id, reason,
            )
            return {
                "kit_id": child_id,
                "parent_kit_id": kit_id,
                "status": "failed",
                "error": reason,
            }

        # Update child kit metadata
        child_kit.local_path = str(filepath)
        child_kit.filename = filepath.name
        child_kit.file_size = filepath.stat().st_size
        child_kit.status = KitStatus.DOWNLOADED

        suffix = filepath.suffix.lower()
        mime_map = {
            ".html": "text/html",
            ".htm": "text/html",
            ".zip": "application/zip",
            ".gz": "application/gzip",
            ".tar": "application/x-tar",
            ".rar": "application/x-rar-compressed",
            ".php": "application/x-php",
            ".eml": "message/rfc822",
        }
        child_kit.mime_type = mime_map.get(suffix, "text/html")

        # Update child source_url to the browser's final URL (relay domain)
        # so each child reflects where its content actually came from.
        if final_url and final_url != parent_kit.source_url:
            child_kit.source_url = final_url

        # AITM URL-fragment extraction.  Attackers smuggle the victim
        # email through the URL fragment (the part after ``#``) so the
        # AITM proxy's client-side JS can pre-fill the fake login form
        # without the email touching the server log.  Pattern observed
        # in the wild on volgograd-consalting / digitaltrustlayer kits.
        # Both the redirect_uri and the original lure URL can carry it.
        if final_url:
            from urllib.parse import unquote

            from darla.models.indicator import Indicator, IndicatorType
            from darla.models.victim import VictimObservationSource
            from darla.services.victim_service import observe_victim_email

            try:
                fragment = urlparse(final_url).fragment or ""
            except Exception:
                fragment = ""
            # Decode percent-encoded fragment (real-world kits URL-
            # encode the email or its base64 form before appending).
            fragment = unquote(fragment)
            # The fragment may be raw email, base64-encoded email, or
            # arbitrary attacker payload.  Pull the first email-shaped
            # substring if any — keeps us robust to attackers
            # appending other state after the email.
            import re as _re
            _frag_email_re = _re.compile(
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
            )
            for match in _frag_email_re.finditer(fragment):
                addr = match.group(0).lower()
                db.add(Indicator(
                    type=IndicatorType.EMAIL,
                    value=addr,
                    context="aitm_url_fragment",
                    source_file=final_url[:500],
                    confidence=85,
                    kit_id=child_kit.id,
                ))
                observe_victim_email(
                    db, child_kit.id, addr,
                    VictimObservationSource.AITM_URL_FRAGMENT,
                )

        # Mark parent as ANALYZED (first render only) — it keeps its
        # httpx-downloaded content (the raw JS loader / first-stage payload)
        if parent_kit.status != KitStatus.ANALYZED:
            parent_kit.status = KitStatus.ANALYZED

        # --- Compute hashes ---
        # IMPORTANT: ``no_autoflush`` is preserved for dedup-query safety
        # even though the UNIQUE index on ``kits.sha256`` was dropped in
        # migration ``w3s9t0u1v2n4``.  The wrap protects against any
        # future flush ordering surprise; it's cheap.
        child_hashes = do_hash(filepath)
        child_kit.sha256 = child_hashes.sha256
        child_kit.md5 = child_hashes.md5
        child_kit.sha1 = child_hashes.sha1
        child_kit.tlsh = child_hashes.tlsh

        threshold = settings.browser_dedup_tlsh_threshold

        # --- Ancestor chain dedup (stuck-at-gate detection) ---
        # Walk parent → grandparent → … → root.  If the child's content
        # matches any ancestor, it's stuck at the same protection gate.
        # Ancestors are always in the same investigation by construction,
        # so these matches always trigger the FAILED-redundancy path
        # (not the cross-investigation correlation path).
        matched_kit: Kit | None = None
        match_reason: str = ""
        stuck_at_gate = False

        with db.no_autoflush:
            ancestors = _walk_ancestor_chain(
                db, child_kit, settings.chain_max_depth,
            )
            matched_ancestor, ancestor_reason = _find_ancestor_match(
                child_kit, ancestors, threshold,
            )
            if matched_ancestor is not None:
                matched_kit = matched_ancestor
                match_reason = ancestor_reason
                stuck_at_gate = True

            # --- Direct sibling dedup (relay pool exhaustion) ---
            # Same parent_kit_id → same investigation by construction.
            if matched_kit is None:
                siblings = _get_direct_siblings(db, child_kit)
                for sibling in siblings:
                    matched, detail = _content_matches(
                        child_hashes.tlsh, child_hashes.sha256,
                        sibling.tlsh, sibling.sha256,
                        threshold,
                    )
                    if matched:
                        matched_kit = sibling
                        match_reason = (
                            f"Sibling duplicate of kit {sibling.id} ({detail})"
                        )
                        break

            # --- Cross-chain SHA256 dedup ---
            # Catches kits across DIFFERENT parent chains hitting the
            # same attacker asset.  This is the only dedup path that
            # can match a kit in a *different investigation*; ancestor
            # and direct-sibling matches above are always within the
            # same investigation.
            if matched_kit is None and child_hashes.sha256:
                existing = find_sha256_match(
                    db, child_hashes.sha256, child_kit.id,
                    child_kit.investigation_id,
                )
                if existing is not None:
                    matched_kit = existing
                    match_reason = (
                        f"Cross-chain SHA256 match with kit {existing.id}"
                    )

        # --- Apply dedup / correlation result ---
        # The decision tree:
        #
        #   match_kit is None         → unique content, proceed with full
        #                               analysis chain dispatch (fall through)
        #   same investigation        → redundant work in the same chain
        #                               (e.g. CF Turnstile re-render loop or
        #                               relay-pool exhaustion).  Mark FAILED,
        #                               keep hashes (UNIQUE was dropped, we
        #                               want SHA256/TLSH search to surface
        #                               duplicate kits as additional hits).
        #   cross investigation       → CORRELATION, not redundancy.  Two
        #                               investigations independently hit
        #                               the same attacker asset (e.g. an
        #                               AITM proxy serving identical bytes
        #                               to multiple victim chains).  Set
        #                               ``duplicate_of_kit_id`` as a soft
        #                               link but proceed with full
        #                               analysis so investigation B's
        #                               view records its own IOCs / YARA
        #                               matches / similarity edges.
        if matched_kit is not None:
            same_investigation = (
                child_kit.investigation_id == matched_kit.investigation_id
            )
            child_kit.duplicate_of_kit_id = matched_kit.id

            if not same_investigation:
                # Cross-investigation correlation — preserve full analysis.
                logger.info(
                    "Kit %s: cross-investigation correlation with kit %s "
                    "(%s, investigations %s vs %s) — proceeding with "
                    "full analysis",
                    child_id, matched_kit.id, match_reason,
                    child_kit.investigation_id, matched_kit.investigation_id,
                )
                # Fall through to the success path below.  Don't set
                # FAILED, don't return, don't dispatch pool-enum
                # re-render (correlation match isn't a relay-pool
                # rotation signal).
                matched_kit = None  # clear so the FAILED branch is skipped
                stuck_at_gate = False

        if matched_kit is not None:
            # Same-investigation redundancy — drop this rendering.  Files
            # stay on disk; we keep hashes intact for SHA256/TLSH search.
            child_kit.status = KitStatus.FAILED
            child_kit.error_message = match_reason
            db.commit()

            logger.info("Kit %s: %s", child_id, match_reason)

            duplicate_of_str = str(child_kit.duplicate_of_kit_id)

            if stuck_at_gate:
                # Stuck at a protection gate — re-rendering the same
                # parent won't help.  Don't schedule another attempt.
                _complete_investigation_if_done(db, child_kit)
                return {
                    "kit_id": child_id,
                    "parent_kit_id": kit_id,
                    "status": "stuck_at_gate",
                    "duplicate_of": duplicate_of_str,
                    "reason": match_reason,
                }

            # Sibling duplicate — relay pool may still have new domains.
            # Pre-create the next child kit so the dispatched task is
            # idempotent on redelivery.
            next_dupes = consecutive_dupes + 1
            if next_dupes < settings.browser_render_pool_stop:
                next_child, skip_reason = (
                    precreate_browser_render_child_kit(db, parent_kit)
                )
                if next_child is not None:
                    db.commit()
                    browser_download_kit.apply_async(
                        args=[kit_id, str(next_child.id), next_dupes],
                    )
                else:
                    logger.info(
                        "Kit %s: pool-enum re-dispatch suppressed — %s",
                        kit_id, skip_reason,
                    )
            # After the re-dispatch decision, so a just-precreated render
            # (DOWNLOADING) keeps the investigation open.
            _complete_investigation_if_done(db, child_kit)
            return {
                "kit_id": child_id,
                "parent_kit_id": kit_id,
                "status": "duplicate",
                "duplicate_of": duplicate_of_str,
                "reason": match_reason,
            }

        db.commit()

        # Segment the render into stages (lure → gate → cred page) and
        # store per-stage fingerprints + content-addressed resources.
        # Runs in its own transaction AFTER the render is durably
        # committed, so a manifest problem can only roll back the stage
        # work — never the kit metadata, hashes, or fragment IOCs above.
        try:
            from darla.services.stage_service import build_and_store_stages

            build_and_store_stages(db, child_kit, download_dir)
            db.commit()
        except Exception as stage_err:
            logger.debug(
                "Kit %s: stage segmentation failed: %s", child_id, stage_err,
            )
            with contextlib.suppress(Exception):
                db.rollback()

        logger.info(
            "Browser downloaded child kit %s (parent %s): %s (%d bytes)",
            child_id, kit_id, filepath.name, child_kit.file_size,
        )

        # Dispatch post-download analysis chain.  Note: cross-
        # investigation correlated kits (``duplicate_of_kit_id`` set,
        # status NOT FAILED — the new branch above) reach this path
        # too — they get full analysis so investigation B's view has
        # its own IOCs / YARA / similarity edges.
        download_result = {
            "kit_id": child_id,
            "parent_kit_id": kit_id,
            "status": "downloaded",
            "filepath": str(filepath),
            "file_size": child_kit.file_size,
            "extract_dir": str(download_dir),
        }
        if child_kit.duplicate_of_kit_id is not None:
            download_result["correlated_with"] = str(child_kit.duplicate_of_kit_id)

        from darla.tasks.analysis import build_post_download_chain

        build_post_download_chain(download_result).apply_async()

        # Re-render to discover more relay variations (reset dupe counter),
        # but only if the browser reached a different domain by a *passive*
        # relay redirect.  Skip when:
        #  - the final URL stays on the lure domain, or on a host the
        #    parent's plain-HTTP redirect chain already reached (email
        #    click-tracker in front of the phish), or
        #  - the final domain was reached by interaction (a CTA click or
        #    email-gate fill) — that path is deterministic and re-rendering
        #    just reproduces the same landing (the wasted duplicate
        #    render seen on email-gate lures), not a rotating pool.
        # Subject to the per-investigation in-flight budget so a single
        # adversarial kit can't dominate the browser worker.
        final_domain = urlparse(final_url).hostname if final_url else None
        if (
            final_domain
            and not interaction_driven
            and final_domain not in _known_landing_hosts(db, parent_kit)
        ):
            next_child, skip_reason = (
                precreate_browser_render_child_kit(db, parent_kit)
            )
            if next_child is not None:
                db.commit()
                browser_download_kit.apply_async(
                    args=[kit_id, str(next_child.id), 0],
                )
                return {**download_result, "rerender_scheduled": True}
            logger.info(
                "Kit %s: relay-rotation re-render suppressed — %s",
                kit_id, skip_reason,
            )

        return download_result

    except Exception as e:
        logger.exception("Browser download error for kit %s: %s", kit_id, e)
        try:
            db.rollback()
            parent_kit = db.query(Kit).filter(
                Kit.id == uuid.UUID(kit_id)
            ).first()
            if parent_kit:
                parent_kit.status = KitStatus.FAILED
                parent_kit.error_message = f"Browser error: {e!s}"[:500]
                db.commit()
        except Exception as exc:
            logger.debug(
                "Failed to mark kit as FAILED during error handling: %s", exc,
            )
        return {"kit_id": kit_id, "status": "failed", "error": str(e)}

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Passive artifact render — EML, SVG, PDF, DOCX screenshots
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.browser.render_artifact",
    bind=True,
    max_retries=0,
    queue="browser",
    soft_time_limit=180,
    time_limit=210,
)
def render_artifact(self, kit_id: str) -> dict:
    """Produce passive visual renders for a kit's underlying file.

    Dispatched in parallel with the analysis chain for any kit whose file
    is an EML, SVG, PDF, or DOCX. Produces ``00_<type>.png`` images under
    ``<download_dir>/_screenshots/`` which the existing screenshot API
    surfaces unchanged.

    Non-fatal: failures are recorded as errors on the AnalysisResult but
    never mark the kit as FAILED.
    """
    settings = get_settings()
    if not getattr(settings, "artifact_render_enabled", True):
        return {"kit_id": kit_id, "rendered": 0, "skipped": "disabled"}

    db = get_sync_db()
    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {"kit_id": kit_id, "rendered": 0, "error": "kit_not_found"}

        if not kit.local_path:
            return {"kit_id": kit_id, "rendered": 0, "skipped": "no_local_path"}

        local = Path(kit.local_path)
        if not local.is_file():
            return {"kit_id": kit_id, "rendered": 0, "error": "file_missing"}

        from darla.analysis.artifact_renderer import (
            classify_artifact,
        )
        from darla.analysis.artifact_renderer import (
            render_artifact as do_render,
        )

        fmt = classify_artifact(local)
        if fmt is None:
            return {"kit_id": kit_id, "rendered": 0, "skipped": "unsupported"}

        # Screenshots live next to any browser-render screenshots under the
        # kit's download directory.  Fall back to the configured root +
        # kit_id when local_path is inside a nested subdir (e.g. a child
        # kit whose local_path points into the parent's _nested_emls dir).
        download_root = Path(settings.kit_download_dir) / kit_id
        # Prefer the parent dir of the file itself when it's already in a
        # per-kit directory; otherwise use the canonical download root.
        candidate = local.parent
        shots_dir = (
            candidate / "_screenshots"
            if (candidate / "_browser_resources").exists()
            else download_root / "_screenshots"
        )

        result = do_render(local, shots_dir, timeout=settings.browser_download_timeout)

        # Record in AnalysisResult so analysts can see what rendered.
        try:
            from darla.models.analysis_result import AnalysisType
            from darla.tasks.analysis import upsert_analysis_result

            upsert_analysis_result(
                db,
                kit_id=kit.id,
                analysis_type=AnalysisType.ARTIFACT_RENDER,
                result_data={
                    "format": result.format,
                    "rendered_files": [Path(p).name for p in result.rendered_files],
                    "stage_labels": result.stage_labels,
                    "errors": result.errors[:10],
                },
                files_processed=len(result.rendered_files),
            )
            db.commit()
        except Exception as rec_err:
            logger.debug(
                "Failed to persist ARTIFACT_RENDER result for %s: %s",
                kit_id, rec_err,
            )
            db.rollback()

        logger.info(
            "Artifact render for kit %s (%s): %d images, %d errors",
            kit_id, result.format, len(result.rendered_files), len(result.errors),
        )
        return {
            "kit_id": kit_id,
            "rendered": len(result.rendered_files),
            "format": result.format,
            "errors": result.errors[:5],
        }

    except Exception as e:
        logger.exception("render_artifact failed for kit %s", kit_id)
        return {"kit_id": kit_id, "rendered": 0, "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Active SVG detonation — JS-enabled render + network interception.
# Runs as a chain step (not fire-and-forget) so terminal URLs flow into the
# chain crawler inside the same analysis pipeline that already processes the
# originating EML submission.
# ---------------------------------------------------------------------------

def _iter_svg_attachments(extract_dir: Path, limit: int) -> list[Path]:
    """Yield SVG attachments under *extract_dir*, tolerating trailing-dot names.

    Attacker attachments sometimes land as ``ATT021.svg..`` where ``.suffix``
    returns ``"."``. We strip trailing dots/spaces from the filename so the
    real extension surfaces.
    """
    svgs: list[Path] = []
    try:
        for path in extract_dir.rglob("*"):
            if not path.is_file():
                continue
            # Skip anything under our own output dirs to avoid infinite loops
            # on re-analysis (resources_saved would grow each run).
            if any(
                part in {"_browser_resources", "_screenshots"}
                for part in path.parts
            ):
                continue
            name = path.name.rstrip(". ")
            if Path(name).suffix.lower() == ".svg":
                svgs.append(path)
                if len(svgs) >= limit:
                    break
    except Exception as exc:  # pragma: no cover — IO failure only
        logger.debug("SVG enumeration failed under %s: %s", extract_dir, exc)
    return svgs


def _resolve_recipient_email(db, kit: Kit) -> str | None:
    """Best-effort recipient-email lookup for pre-seeding ``window.dawa``.

    We check, in order:
      1. The kit's own ``local_path`` if it is an EML.
      2. The parent chain — nested EML children inherit the recipient from
         the outer envelope in real attacks.
    Returns ``None`` when nothing usable is found. Safe to call on kits
    that never had an EML involved; callers tolerate ``None``.
    """
    from darla.analysis.eml_parser import EMLParser

    def _parse(p: Path) -> str | None:
        try:
            if not p.is_file() or p.suffix.lower() != ".eml":
                return None
            parsed = EMLParser().parse(str(p))
            to_hdr = (parsed.headers or {}).get("To")
            if not to_hdr:
                return None
            # Pull the first address out — addresses can be "Name <a@b>" or
            # comma-separated. We want only the bare e-mail.
            import email.utils as _eu
            addrs = _eu.getaddresses([to_hdr])
            for _name, addr in addrs:
                if addr and "@" in addr:
                    return addr.strip()
        except Exception as exc:
            logger.debug("Failed to parse recipient from %s: %s", p, exc)
        return None

    if kit.local_path:
        email_addr = _parse(Path(kit.local_path))
        if email_addr:
            return email_addr

    # Walk up to 3 parents — nested-EML chains shouldn't be deeper than that.
    current = kit
    for _ in range(3):
        if not current.parent_kit_id:
            break
        parent = db.query(Kit).filter(Kit.id == current.parent_kit_id).first()
        if not parent:
            break
        if parent.local_path:
            email_addr = _parse(Path(parent.local_path))
            if email_addr:
                return email_addr
        current = parent
    return None


@celery_app.task(
    name="darla.tasks.browser.execute_svgs_active",
    bind=True,
    max_retries=0,
    queue="browser",
    soft_time_limit=240,
    time_limit=300,
)
def execute_svgs_active(self, prev_result: dict) -> dict:
    """Detonate SVG attachments with JS enabled and capture outbound URLs.

    Placed in the analysis chain between ``fetch_external_js`` and
    ``crawl_chain`` so that terminal URLs discovered by active rendering
    merge with the httpx-fetched set before child-kit spawning. The task
    no-ops cleanly when:

      * the feature is disabled in settings,
      * the kit has no extract_dir (non-archive single files),
      * no SVGs exist under the extract tree,
      * Camoufox is not installed in the worker image.

    Returns ``prev_result`` augmented with ``svg_active_terminal_urls`` so
    the existing ``crawl_chain`` pipeline can route them into child kits.
    """
    kit_id = prev_result.get("kit_id")
    if prev_result.get("status") == "failed" or not kit_id:
        return prev_result

    from darla.config import get_settings
    settings = get_settings()
    if not getattr(settings, "svg_active_exec_enabled", True):
        return {**prev_result, "svg_active_skipped": "disabled"}

    extract_dir = prev_result.get("extract_dir")
    # Single-file EML kits land on local_path instead of an extract_dir; the
    # fetch_external_js step synthesizes an extract_dir for them, so by the
    # time we run here, prev_result.extract_dir is usually populated even
    # for flat submissions. Fall back to local_path's parent if missing.
    if not extract_dir:
        filepath = prev_result.get("filepath")
        if filepath and Path(filepath).is_file():
            extract_dir = str(Path(filepath).parent)
    if not extract_dir:
        return {**prev_result, "svg_active_skipped": "no_extract_dir"}

    extract_path = Path(extract_dir)
    if not extract_path.is_dir():
        return {**prev_result, "svg_active_skipped": "extract_dir_missing"}

    svg_paths = _iter_svg_attachments(
        extract_path, limit=settings.svg_active_exec_max_per_kit,
    )
    if not svg_paths:
        return {**prev_result, "svg_active_skipped": "no_svgs"}

    db = get_sync_db()
    import time as _time
    start = _time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "svg_active_skipped": "kit_not_found"}

        # Only run on kits inside an investigation — otherwise the captured
        # URLs have nowhere to go and we're burning browser budget for
        # nothing. (render_artifact stays live for preview regardless.)
        if not kit.investigation_id:
            return {**prev_result, "svg_active_skipped": "no_investigation"}

        # Depth guard — don't let a chain-spawned child re-detonate SVGs
        # already seen upstream.
        if getattr(kit, "chain_depth", 0) >= settings.chain_max_depth:
            return {**prev_result, "svg_active_skipped": "max_depth"}

        from darla.analysis.browser_svg_runner import (
            derive_dawa_from_email,
            execute_svg_with_capture,
        )
        from darla.models.analysis_result import AnalysisType
        from darla.tasks.analysis import upsert_analysis_result

        recipient = _resolve_recipient_email(db, kit)
        dawa_value = derive_dawa_from_email(recipient)

        # Output directory — reuse the kit's download dir so screenshots
        # and resources live next to passive-render outputs.
        out_dir = Path(settings.kit_download_dir) / kit_id
        out_dir.mkdir(parents=True, exist_ok=True)

        aggregated_urls: list[str] = []
        aggregated_terminals: list[str] = []
        aggregated_navs: list[str] = []
        per_svg: list[dict] = []
        errors: list[str] = []
        total_resources = 0

        seen_u: set[str] = set()
        seen_t: set[str] = set()

        for svg_path in svg_paths:
            try:
                res = execute_svg_with_capture(
                    svg_path, out_dir,
                    dawa_value=dawa_value,
                    timeout=settings.svg_active_exec_timeout,
                    max_requests=settings.svg_active_exec_max_requests,
                )
            except Exception as exc:
                logger.exception(
                    "Active SVG exec crashed for kit %s (%s)",
                    kit_id, svg_path.name,
                )
                errors.append(f"{svg_path.name}:{exc}")
                continue

            for u in res.urls_discovered:
                if u not in seen_u:
                    seen_u.add(u)
                    aggregated_urls.append(u)
            for u in res.terminal_urls:
                if u not in seen_t:
                    seen_t.add(u)
                    aggregated_terminals.append(u)
            for nav in res.navigations:
                if nav not in aggregated_navs:
                    aggregated_navs.append(nav)

            total_resources += res.resources_saved
            per_svg.append({
                "svg": svg_path.name,
                "status": res.status,
                "urls": len(res.urls_discovered),
                "terminal_urls": len(res.terminal_urls),
                "resources_saved": res.resources_saved,
                "network_events": res.network_events,
                "duration_seconds": res.duration_seconds,
                "screenshots": [Path(s).name for s in res.screenshots],
                "error": res.error,
            })
            if res.error:
                errors.append(f"{svg_path.name}:{res.error}")

        duration = _time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.SVG_ACTIVE_EXEC,
            result_data={
                "svgs_processed": len(svg_paths),
                "urls_discovered": aggregated_urls[:100],
                "terminal_urls": aggregated_terminals[:50],
                "navigations": aggregated_navs[:50],
                "resources_saved": total_resources,
                "recipient_dawa_set": dawa_value is not None,
                "per_svg": per_svg,
                "errors": errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=len(svg_paths),
        )
        db.commit()

        logger.info(
            "SVG active exec for kit %s: %d SVGs → %d urls, %d terminals, "
            "%d resources (dawa_set=%s, dur=%.2fs)",
            kit_id, len(svg_paths), len(aggregated_urls),
            len(aggregated_terminals), total_resources,
            dawa_value is not None, duration,
        )

        # Merge terminal URLs with anything the httpx-driven external-JS
        # fetch already discovered, so crawl_chain's existing reader
        # (``external_js_terminal_urls``) picks up both in one list.
        existing_terminals = list(prev_result.get("external_js_terminal_urls", []))
        merged_terminals = existing_terminals + [
            u for u in aggregated_terminals if u not in existing_terminals
        ]

        return {
            **prev_result,
            "svg_active_svgs_processed": len(svg_paths),
            "svg_active_urls": aggregated_urls,
            "svg_active_terminal_urls": aggregated_terminals,
            # crawl_chain reads this key for chain-crawling; augmenting it
            # means we don't need a separate wiring change to spawn kits.
            "external_js_terminal_urls": merged_terminals,
        }

    except Exception as e:
        logger.exception("execute_svgs_active failed for kit %s", kit_id)
        try:
            from darla.models.analysis_result import AnalysisType
            from darla.tasks.analysis import upsert_analysis_result
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.SVG_ACTIVE_EXEC,
                    result_data={"error": str(e)},
                    duration_seconds=round(_time.time() - start, 3),
                    error=str(e),
                )
                db.commit()
        except Exception:
            pass
        return {**prev_result, "svg_active_error": str(e)}
    finally:
        db.close()
