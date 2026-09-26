"""Analysis pipeline Celery tasks — hash, extract, deobfuscate, extract IOCs."""

import contextlib
import logging
import os
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from celery import chain
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.indicator import Indicator
from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


def upsert_analysis_result(db, **kwargs) -> None:
    """Insert or update an AnalysisResult, deduplicating on (kit_id, analysis_type).

    Accepts the same keyword arguments as ``AnalysisResult(...)``.
    On conflict the existing row is updated with the new data.
    """
    import uuid as _uuid

    values = {**kwargs}
    if "id" not in values:
        values["id"] = _uuid.uuid4()

    stmt = pg_insert(AnalysisResult).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_kit_analysis_type",
        set_={
            "result_data": stmt.excluded.result_data,
            "duration_seconds": stmt.excluded.duration_seconds,
            "files_processed": stmt.excluded.files_processed,
            "error": stmt.excluded.error,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    db.execute(stmt)


def _post_download_steps() -> list:
    """Return the analysis chain steps that run after download.

    NOTE: ``correlate_kit_actors`` and ``auto_assign_campaign`` were removed
    from this chain in the PhishMatch manual-first attribution redesign.
    Attribution (kit → actor/campaign/family) is now driven by analyst review
    via the PhishMatch UI.  The tasks themselves still exist in
    ``darla.tasks.correlation`` and ``darla.tasks.campaigns`` and may be
    invoked as *suggestion* generators by the scoring engine, but they no
    longer silently mutate the attribution graph as part of every pipeline run.
    """
    from darla.tasks.browser import execute_svgs_active
    from darla.tasks.chain import crawl_chain, decode_qr_codes, parse_eml

    return [
        compute_hashes.s(),
        extract_archive.s(),
        parse_eml.s(),
        deobfuscate_files.s(),
        decrypt_html_payloads.s(),
        fetch_external_js.s(),
        # Active SVG detonation runs on the ``browser`` queue.  Placing it
        # after the httpx-driven JS fetch but before ``crawl_chain`` lets
        # URLs captured from live rendering merge with statically-fetched
        # terminal URLs into a single chain-crawl batch.
        execute_svgs_active.s(),
        yara_scan.s(),
        extract_iocs.s(),
        decode_qr_codes.s(),
        compute_similarity.s(),
        detect_polymorphism.s(),
        crawl_chain.s(),
        finalize_kit.s(),
    ]


def build_analysis_chain(kit_id: str, force: bool = False) -> chain:
    """Build the full analysis Celery chain for a kit."""
    from darla.tasks.download import download_kit

    steps = _post_download_steps()
    if force:
        # Inject force flag into the chain so compute_hashes skips SHA256 dedup
        steps = [_inject_force.s(), *steps]
        # ...and so download_kit skips its browser-render redundancy check
        return chain(download_kit.s(kit_id, force=True), *steps)
    return chain(download_kit.s(kit_id), *steps)


def build_post_download_chain(download_result: dict) -> chain:
    """Build the analysis chain starting after download (steps 2-14).

    Used by browser_download_kit to continue the pipeline after a
    successful Camoufox download.
    """
    return chain(compute_hashes.si(download_result), *_post_download_steps()[1:])


# ---------------------------------------------------------------------------
# Chain cursor — for resuming stalled chains without restarting the whole
# kit from download_kit.  See ``recover_chain_cursors`` in tasks/recovery.py.
# ---------------------------------------------------------------------------

# Ordered list of post-download chain step names matching ``_post_download_steps()``
# entry-by-entry.  The Celery task_prerun signal looks up the running task's
# fully-qualified name in this map and writes the SHORT name to
# ``Kit.chain_cursor``.  Keep this list synchronized with _post_download_steps().
_CHAIN_STEP_NAME_MAP: dict[str, str] = {
    "darla.tasks.analysis.compute_hashes": "compute_hashes",
    "darla.tasks.analysis.extract_archive": "extract_archive",
    "darla.tasks.chain.parse_eml": "parse_eml",
    "darla.tasks.analysis.deobfuscate_files": "deobfuscate_files",
    "darla.tasks.analysis.decrypt_html_payloads": "decrypt_html_payloads",
    "darla.tasks.analysis.fetch_external_js": "fetch_external_js",
    "darla.tasks.browser.execute_svgs_active": "execute_svgs_active",
    "darla.tasks.analysis.yara_scan": "yara_scan",
    "darla.tasks.analysis.extract_iocs": "extract_iocs",
    "darla.tasks.chain.decode_qr_codes": "decode_qr_codes",
    "darla.tasks.analysis.compute_similarity": "compute_similarity",
    "darla.tasks.analysis.detect_polymorphism": "detect_polymorphism",
    "darla.tasks.chain.crawl_chain": "crawl_chain",
    "darla.tasks.analysis.finalize_kit": "finalize_kit",
}

# Reverse-ordered list used by ``post_download_steps_from_cursor`` to slice
# the chain at a resume point.  Order MUST match _CHAIN_STEP_NAME_MAP value
# order which MUST match _post_download_steps() invocation order.
_CHAIN_STEP_ORDER: tuple[str, ...] = (
    "compute_hashes",
    "extract_archive",
    "parse_eml",
    "deobfuscate_files",
    "decrypt_html_payloads",
    "fetch_external_js",
    "execute_svgs_active",
    "yara_scan",
    "extract_iocs",
    "decode_qr_codes",
    "compute_similarity",
    "detect_polymorphism",
    "crawl_chain",
    "finalize_kit",
)


def post_download_steps_from_cursor(cursor: str | None) -> list:
    """Return chain step signatures starting at ``cursor`` (inclusive).

    The cursor records "this step started but may not have completed";
    on resume we re-run from the cursor to be safe — every step must be
    idempotent.  Returns an empty list when ``cursor`` is unknown or
    after the last step.
    """
    if not cursor or cursor not in _CHAIN_STEP_ORDER:
        return []
    cursor_index = _CHAIN_STEP_ORDER.index(cursor)
    full_steps = _post_download_steps()
    return full_steps[cursor_index:]


# Celery signal: record the cursor at every chain-step task start.
# Using a signal (rather than touching 14 task bodies) keeps the cursor
# logic in one place and means new steps added later get covered
# automatically as long as their fully-qualified name is added to
# ``_CHAIN_STEP_NAME_MAP``.
from celery.signals import task_prerun  # noqa: E402


@task_prerun.connect
def _record_chain_cursor(
    sender=None, task_id=None, task=None, args=None, kwargs=None, **_,
):
    """Write ``Kit.chain_cursor`` at the start of each post-download step.

    The chain steps all take a single positional ``prev_result`` dict
    that carries ``kit_id``.  We use that to address the row.  Any
    failure here is logged and swallowed — chain progress must not
    block on bookkeeping.
    """
    if task is None:
        return
    step_name = _CHAIN_STEP_NAME_MAP.get(task.name)
    if step_name is None:
        return
    if not args or not isinstance(args[0], dict):
        return
    kit_id_str = args[0].get("kit_id")
    if not kit_id_str:
        return
    db = None
    try:
        db = get_sync_db()
        db.query(Kit).filter(Kit.id == uuid.UUID(kit_id_str)).update(
            {"chain_cursor": step_name},
            synchronize_session=False,
        )
        db.commit()
    except Exception as exc:
        logger.warning(
            "Failed to record chain_cursor=%s for kit %s: %s",
            step_name, kit_id_str, exc,
        )
        if db is not None:
            with contextlib.suppress(Exception):
                db.rollback()
    finally:
        if db is not None:
            db.close()


@celery_app.task(name="darla.tasks.analysis._inject_force", queue="analysis")
def _inject_force(prev_result: dict) -> dict:
    """Stamp force=True onto the chain result dict."""
    return {**prev_result, "force": True}


@celery_app.task(
    name="darla.tasks.analysis.compute_hashes",
    bind=True,
    queue="analysis",
)
def compute_hashes(self, prev_result: dict) -> dict:
    """Compute SHA256, MD5, SHA1, and TLSH hashes for the kit archive."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") in ("failed", "browser_retry"):
        # browser_retry → browser worker handles the rest via its own chain
        return {**prev_result, "status": "failed"}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.local_path:
            return {**prev_result, "status": "failed", "error": "no_local_file"}

        # If hashes were already computed (e.g. by browser_download_kit
        # for TLSH dedup), skip re-computation.
        if kit.sha256 and kit.tlsh:
            logger.info("Kit %s: hashes already computed, skipping", kit_id)
            return {**prev_result, "sha256": kit.sha256, "hashed": True}

        kit.status = KitStatus.ANALYZING
        db.commit()

        from darla.analysis.hasher import compute_hashes as do_hash

        result = do_hash(kit.local_path)

        # Check for duplicate SHA256 (skip when force-resubmitted and
        # skip the empty-file hash — every 0-byte download shares it).
        #
        # The semantics changed in migration ``w3s9t0u1v2n4``: same
        # SHA256 in the SAME investigation is still treated as
        # redundant work (mark FAILED + set duplicate_of_kit_id), but
        # cross-investigation matches are CORRELATION SIGNALS, not
        # redundancy.  Investigation B independently encountering an
        # AITM proxy already seen in investigation A should keep its
        # own analyzed kit so its IOCs / YARA matches / similarity
        # edges are recorded under the right investigation.  The
        # ``duplicate_of_kit_id`` pointer carries the correlation back
        # to the canonical sibling.
        #
        # NULL investigation_id on both sides (feed-ingested kits not
        # yet promoted) is treated as the same "investigation" so feed
        # dedup behavior is preserved — two identical feed arrivals
        # collapse to one.
        from darla.tasks.browser import EMPTY_SHA256, find_sha256_match

        if not prev_result.get("force") and result.sha256 != EMPTY_SHA256:
            existing = find_sha256_match(
                db, result.sha256, kit.id, kit.investigation_id,
            )

            if existing:
                same_investigation = (
                    kit.investigation_id == existing.investigation_id
                )
                if same_investigation:
                    kit.status = KitStatus.FAILED
                    kit.error_message = (
                        f"Duplicate of kit {existing.id} (same SHA256)"
                    )
                    kit.duplicate_of_kit_id = existing.id
                    db.commit()
                    logger.info(
                        "Kit %s is same-investigation duplicate of %s "
                        "(sha256=%s)",
                        kit_id, existing.id, result.sha256[:16],
                    )
                    return {
                        **prev_result,
                        "status": "failed",
                        "error": "duplicate_sha256",
                    }
                # Cross-investigation: set correlation pointer but keep
                # the kit going through analysis.  Hashes will be
                # written below (the UNIQUE constraint was dropped in
                # migration w3s9t0u1v2n4 specifically to allow this).
                kit.duplicate_of_kit_id = existing.id
                logger.info(
                    "Kit %s: cross-investigation correlation with kit %s "
                    "(same SHA256, investigations %s vs %s) — "
                    "proceeding with full analysis",
                    kit_id, existing.id,
                    kit.investigation_id, existing.investigation_id,
                )

        kit.sha256 = result.sha256
        kit.md5 = result.md5
        kit.sha1 = result.sha1
        kit.tlsh = result.tlsh

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.HASH,
            result_data={
                "sha256": result.sha256,
                "md5": result.md5,
                "sha1": result.sha1,
                "tlsh": result.tlsh,
                "file_size": result.file_size,
            },
            duration_seconds=round(duration, 3),
        )
        db.commit()

        logger.info("Hashes computed for kit %s: sha256=%s", kit_id, result.sha256[:16])

        # Fire a parallel artifact render (EML/SVG/PDF/DOCX → _screenshots).
        # Guarded so one-shot failures never break the analysis chain and
        # already-rendered kits (e.g. reanalysis retries) don't re-queue.
        try:
            settings = get_settings()
            if getattr(settings, "artifact_render_enabled", True):
                from darla.analysis.artifact_renderer import classify_artifact
                from darla.tasks.browser import render_artifact

                if kit.local_path and classify_artifact(Path(kit.local_path)):
                    render_artifact.apply_async(args=[kit_id])
        except Exception as rr_err:
            logger.debug(
                "Failed to dispatch render_artifact for %s: %s", kit_id, rr_err,
            )

        return {
            **prev_result,
            "sha256": result.sha256,
            "hashed": True,
        }

    except Exception as e:
        logger.exception("Error hashing kit %s: %s", kit_id, e)
        try:
            db.rollback()
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.analysis.extract_archive",
    bind=True,
    queue="analysis",
)
def extract_archive(self, prev_result: dict) -> dict:
    """Extract the kit archive into a directory for analysis.

    Skips extraction for non-archive files (HTML pages, etc.) and passes
    them through so IOC extraction can scan the raw downloaded file.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    # Skip extraction for non-archive files
    filepath = prev_result.get("filepath", "")
    if filepath:
        archive_extensions = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".rar"}
        suffixes = {s.lower() for s in Path(filepath).suffixes}
        if not suffixes & archive_extensions:
            logger.info(
                "Kit %s is not an archive, skipping extraction", kit_id
            )
            return {**prev_result, "extracted": False, "skipped_extraction": True}

    settings = get_settings()
    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.local_path:
            return {**prev_result, "status": "failed", "error": "no_local_file"}

        extract_dir = str(Path(settings.kit_extract_dir) / kit_id)

        from darla.analysis.extractor import ArchiveExtractor

        extractor = ArchiveExtractor()
        result = extractor.extract(kit.local_path, extract_dir)

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.IOC_EXTRACTION,
            result_data={
                "step": "extraction",
                "file_count": result.file_count,
                "total_size": result.total_size,
                "errors": result.errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=result.file_count,
        )
        db.commit()

        logger.info(
            "Extracted kit %s: %d files, %d bytes",
            kit_id, result.file_count, result.total_size,
        )
        return {
            **prev_result,
            "extract_dir": extract_dir,
            "file_count": result.file_count,
            "extracted": True,
        }

    except Exception as e:
        logger.exception("Error extracting kit %s: %s", kit_id, e)
        try:
            db.rollback()
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


def _looks_like_html(filepath: Path) -> bool:
    """Sniff first 512 bytes for HTML markers (extension-agnostic)."""
    try:
        with open(filepath, "rb") as f:
            head = f.read(512).lower()
        return any(marker in head for marker in (
            b"<!doctype", b"<html", b"<head", b"<body", b"<script",
        ))
    except Exception:
        return False


@celery_app.task(
    name="darla.tasks.analysis.deobfuscate_files",
    bind=True,
    queue="analysis",
)
def deobfuscate_files(self, prev_result: dict) -> dict:
    """Deobfuscate PHP and HTML files in the kit directory."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    # Need at least one source of files to process
    if not extract_dir and not filepath:
        return {**prev_result, "deobfuscated": False}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from darla.analysis.deobfuscator import (
            HTMLDeobfuscator,
            JSDeobfuscator,
            PHPDeobfuscator,
        )

        php_deobfuscator = PHPDeobfuscator()
        html_deobfuscator = HTMLDeobfuscator()
        js_deobfuscator = JSDeobfuscator()
        deob_results = []
        files_processed = 0

        # Collect all candidate files
        candidates: list[Path] = []
        base_dir: Path | None = None

        if extract_dir:
            base_dir = Path(extract_dir)
            candidates.extend(base_dir.rglob("*"))
        elif filepath:
            base_dir = Path(filepath).parent
            candidates.append(Path(filepath))

        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                # PHP deobfuscation — match by extension
                if candidate.suffix.lower() == ".php":
                    result = php_deobfuscator.deobfuscate_file(str(candidate))
                    if result.layers_unwrapped > 0:
                        candidate.write_text(
                            result.deobfuscated_content, encoding="utf-8",
                        )
                        deob_results.append({
                            "file": str(candidate.relative_to(base_dir)),
                            "layers": result.layers_unwrapped,
                            "techniques": result.techniques_found,
                        })
                    files_processed += 1

                # HTML deobfuscation — sniff content for HTML markers
                if _looks_like_html(candidate):
                    result = html_deobfuscator.deobfuscate_file(
                        str(candidate),
                    )
                    if result.layers_unwrapped > 0:
                        candidate.write_text(
                            result.deobfuscated_content, encoding="utf-8",
                        )
                        deob_results.append({
                            "file": str(candidate.relative_to(base_dir)),
                            "layers": result.layers_unwrapped,
                            "techniques": result.techniques_found,
                        })
                    files_processed += 1

                # JS XOR+base64 deobfuscation — HTML/JS files with eval chains
                if (
                    candidate.suffix.lower() in (".js", ".html", ".htm")
                    or _looks_like_html(candidate)
                ):
                    result = js_deobfuscator.deobfuscate_file(str(candidate))
                    if result.layers_unwrapped > 0:
                        # Write decoded output as companion file (preserve original)
                        deob_path = candidate.with_suffix(".deob.js")
                        deob_path.write_text(
                            result.deobfuscated_content, encoding="utf-8",
                        )
                        deob_results.append({
                            "file": str(candidate.relative_to(base_dir)),
                            "layers": result.layers_unwrapped,
                            "techniques": result.techniques_found,
                            "deob_file": str(deob_path.relative_to(base_dir)),
                        })
                    files_processed += 1

                # SVG inline <script> bodies — phishing SVGs carry their JS
                # loader inside <script>...</script>, often atob/XOR-obfuscated.
                # Extract each body, deobfuscate it, and drop the plaintext
                # next to the SVG as a sibling .deob.js so the downstream
                # external-JS fetcher can pull the terminal URL out of it.
                _svg_suffix = Path(
                    candidate.name.rstrip(". ")
                ).suffix.lower()
                if _svg_suffix == ".svg":
                    try:
                        from darla.analysis.svg_inspector import (
                            extract_inline_script_bodies,
                        )
                        raw_svg = candidate.read_bytes()
                        bodies = extract_inline_script_bodies(raw_svg)
                    except Exception as svg_err:
                        logger.debug(
                            "SVG script-body extract failed for %s: %s",
                            candidate, svg_err,
                        )
                        bodies = []

                    for idx, body in enumerate(bodies):
                        if not body or len(body) < 20:
                            continue
                        try:
                            result = js_deobfuscator.deobfuscate(body)
                        except Exception as deob_err:
                            logger.debug(
                                "SVG inline-JS deobf failed for %s#%d: %s",
                                candidate, idx, deob_err,
                            )
                            continue
                        # Even if the deobfuscator unwrapped nothing, the raw
                        # body itself may contain plaintext URLs worth
                        # scanning. Emit a sibling file in both cases so
                        # fetch_external_js can hit it.
                        content_out = (
                            result.deobfuscated_content
                            if result.layers_unwrapped > 0
                            else body
                        )
                        deob_path = candidate.parent / (
                            f"{candidate.stem}.script{idx}.deob.js"
                        )
                        try:
                            deob_path.write_text(
                                content_out, encoding="utf-8",
                            )
                        except Exception as write_err:
                            logger.debug(
                                "SVG deob write failed for %s: %s",
                                deob_path, write_err,
                            )
                            continue
                        if result.layers_unwrapped > 0:
                            deob_results.append({
                                "file": str(candidate.relative_to(base_dir)),
                                "layers": result.layers_unwrapped,
                                "techniques": result.techniques_found,
                                "deob_file": str(deob_path.relative_to(base_dir)),
                                "source": "svg_inline_script",
                                "script_index": idx,
                            })
                    files_processed += 1
            except Exception as e:
                logger.debug("Failed to deobfuscate %s: %s", candidate, e)

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.DEOBFUSCATION,
            result_data={
                "files_deobfuscated": len(deob_results),
                "details": deob_results[:50],
            },
            duration_seconds=round(duration, 3),
            files_processed=files_processed,
        )
        db.commit()

        logger.info(
            "Deobfuscation for kit %s: %d/%d files had obfuscation",
            kit_id, len(deob_results), files_processed,
        )
        return {
            **prev_result,
            "deobfuscated": True,
            "files_deobfuscated": len(deob_results),
        }

    except Exception as e:
        logger.exception("Error deobfuscating kit %s: %s", kit_id, e)
        try:
            db.rollback()
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.analysis.decrypt_html_payloads",
    bind=True,
    queue="analysis",
)
def decrypt_html_payloads(self, prev_result: dict) -> dict:
    """Detect and decrypt AES-GCM encrypted HTML phishing pages."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return {**prev_result, "html_decrypted": False}

    from darla.analysis.html_decryptor import HTMLDecryptor

    decryptor = HTMLDecryptor()
    decrypted_count = 0
    results_detail = []

    try:
        if extract_dir:
            # Scan all files in extract directory — encrypted pages may lack
            # .html extension (e.g. Cloudflare Workers session-ID filenames)
            for candidate in Path(extract_dir).rglob("*"):
                if not candidate.is_file():
                    continue
                # Skip known non-HTML (images, archives, etc.)
                skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                            ".zip", ".gz", ".tar", ".rar", ".pdf", ".woff",
                            ".woff2", ".ttf", ".eot", ".css", ".map"}
                if candidate.suffix.lower() in skip_ext:
                    continue
                result = decryptor.detect_and_decrypt(str(candidate))
                if result.success:
                    decrypted_count += 1
                    results_detail.append({
                        "file": str(candidate.relative_to(extract_dir)),
                        "type": result.encryption_type,
                    })
        else:
            # Single file — scan it directly regardless of extension
            # (downloads are often saved as download.bin)
            result = decryptor.detect_and_decrypt(filepath)
            if result.success:
                decrypted_count += 1
                # Create an extract_dir so downstream tasks scan both files
                kit_dir = str(Path(filepath).parent)
                new_extract_dir = os.path.join(kit_dir, "extracted")
                os.makedirs(new_extract_dir, exist_ok=True)
                # Copy original into extract_dir
                import shutil
                shutil.copy2(filepath, new_extract_dir)
                # Move decrypted file into extract_dir
                decrypted_path = Path(result.decrypted_file)
                shutil.move(str(decrypted_path), new_extract_dir)
                extract_dir = new_extract_dir
                results_detail.append({
                    "file": Path(filepath).name,
                    "type": result.encryption_type,
                })

        if decrypted_count > 0:
            logger.info(
                "Decrypted %d HTML payload(s) in kit %s",
                decrypted_count, kit_id,
            )

        return {
            **prev_result,
            "html_decrypted": decrypted_count > 0,
            "files_decrypted": decrypted_count,
            "extract_dir": extract_dir or prev_result.get("extract_dir"),
        }

    except Exception as e:
        logger.warning("HTML decryption error for kit %s: %s", kit_id, e)
        # Non-fatal — continue pipeline with original files
        return {**prev_result, "html_decrypted": False}


@celery_app.task(
    name="darla.tasks.analysis.extract_iocs",
    bind=True,
    queue="analysis",
    soft_time_limit=300,   # 5 min — raises SoftTimeLimitExceeded
    time_limit=330,        # 5.5 min — SIGKILL if soft limit is caught/ignored
)
def extract_iocs(self, prev_result: dict) -> dict:
    """Extract IOCs from kit files (extracted archive or single downloaded file)."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return {**prev_result, "iocs_extracted": 0}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from darla.analysis.ioc_engine import IOCExtractor

        extractor = IOCExtractor(source_url=kit.source_url)
        if extract_dir:
            result = extractor.scan_directory(extract_dir)
        else:
            result = extractor.scan_file(filepath)

        # Structured network-IOC extraction from requests.json (browser
        # render log).  Parses JSON and classifies each URL's origin
        # instead of regex-scraping the file as if it were free text.
        if extract_dir:
            requests_json = Path(extract_dir) / "requests.json"
            if requests_json.exists():
                network_iocs = extractor.extract_network_iocs_from_requests_json(
                    str(requests_json),
                )
                result.iocs.extend(network_iocs)
                result.iocs = extractor._deduplicate(result.iocs)

        # Store file-based indicators
        for ioc in result.iocs:
            indicator = Indicator(
                type=ioc.type,
                value=ioc.value,
                context=ioc.context,
                source_file=ioc.source_file,
                confidence=ioc.confidence,
                kit_id=kit.id,
            )
            db.add(indicator)

        # ------------------------------------------------------------------
        # Network-layer IOC extraction
        # Domains come from URLs we already know (source_url, redirect chain).
        # IPs come from DNS resolution at download time.
        # These are high-confidence because they come from actual connections,
        # not regex scraping of page content.
        # ------------------------------------------------------------------
        from darla.analysis.patterns import BENIGN_URL_ROOT_DOMAINS, extract_root_domain
        from darla.models.indicator import IndicatorType

        network_iocs_added = 0
        seen_values: set[str] = {ioc.value for ioc in result.iocs}
        redirect_chain = prev_result.get("redirect_chain", {})

        # Collect all URLs involved in this kit's network activity
        # Skip file:// URLs — they're local uploads, not network-derived IOCs
        network_urls: list[str] = []
        if kit.source_url and not kit.source_url.startswith("file://"):
            network_urls.append(kit.source_url)
        for hop in redirect_chain.get("hops", []):
            if hop.get("url"):
                network_urls.append(hop["url"])
            if hop.get("location"):
                network_urls.append(hop["location"])
        final_url = redirect_chain.get("final_url")
        if final_url:
            network_urls.append(final_url)

        # Extract unique domains from network URLs
        for url in network_urls:
            try:
                hostname = urlparse(url).hostname
            except Exception:
                continue
            if not hostname:
                continue
            domain = hostname.lower()
            root = extract_root_domain(domain)
            if root in BENIGN_URL_ROOT_DOMAINS:
                continue
            if domain in seen_values:
                continue
            seen_values.add(domain)
            # Also dedup against investigation-wide indicators
            if kit.investigation_id:
                existing = db.query(Indicator.id).join(Kit).filter(
                    Indicator.type == IndicatorType.DOMAIN,
                    Indicator.value == domain,
                    Kit.investigation_id == kit.investigation_id,
                ).first()
                if existing:
                    continue
            db.add(Indicator(
                type=IndicatorType.DOMAIN,
                value=domain,
                context="redirect_chain" if redirect_chain else "source_url",
                source_file=None,
                confidence=95,
                kit_id=kit.id,
            ))
            network_iocs_added += 1

        # Resolve IP from the kit's final destination (or source URL)
        resolve_target = final_url or kit.source_url
        if resolve_target and resolve_target.startswith("file://"):
            resolve_target = None
        if resolve_target and kit.discovery_method != "browser_render":
            try:
                import socket
                target_host = urlparse(resolve_target).hostname
                if target_host:
                    ip = socket.gethostbyname(target_host)
                    if (
                        ip
                        and ip not in seen_values
                        and not ip.startswith(("10.", "192.168.", "127."))
                    ):
                        seen_values.add(ip)
                        # Dedup against investigation
                        existing_ip = None
                        if kit.investigation_id:
                            existing_ip = db.query(Indicator.id).join(Kit).filter(
                                Indicator.type == IndicatorType.IP_ADDRESS,
                                Indicator.value == ip,
                                Kit.investigation_id == kit.investigation_id,
                            ).first()
                        if not existing_ip:
                            db.add(Indicator(
                                type=IndicatorType.IP_ADDRESS,
                                value=ip,
                                context=f"dns_resolution:{target_host}",
                                source_file=None,
                                confidence=95,
                                kit_id=kit.id,
                            ))
                            network_iocs_added += 1
            except Exception as e:
                logger.debug("DNS resolution failed for %s: %s", resolve_target, e)

        # Add the kit source URL as an automatic IOC — but skip for
        # browser_render children since their URL is the same as the parent's.
        added_source_url = False
        if (
            kit.source_url
            and kit.discovery_method != "browser_render"
            and not kit.source_url.startswith("file://")
        ):
            # Dedup: check if this exact URL is already an indicator in the
            # same investigation (redirect child landing on known URL)
            existing_source = None
            if kit.investigation_id:
                existing_source = db.query(Indicator.id).join(Kit).filter(
                    Indicator.type == IndicatorType.SOURCE_URL,
                    Indicator.value == kit.source_url,
                    Kit.investigation_id == kit.investigation_id,
                ).first()

            if not existing_source:
                source_indicator = Indicator(
                    type=IndicatorType.SOURCE_URL,
                    value=kit.source_url,
                    context="kit_source",
                    source_file=None,
                    confidence=100,
                    kit_id=kit.id,
                )
                db.add(source_indicator)
                added_source_url = True

        from darla.analysis.patterns import PATTERN_VERSION

        kit.pattern_version = PATTERN_VERSION

        duration = time.time() - start

        ioc_summary = {}
        for ioc in result.iocs:
            ioc_type = ioc.type.value
            ioc_summary[ioc_type] = ioc_summary.get(ioc_type, 0) + 1

        total_iocs = len(result.iocs)
        if added_source_url:
            ioc_summary["source_url"] = ioc_summary.get("source_url", 0) + 1
            total_iocs += 1

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.IOC_EXTRACTION,
            result_data={
                "step": "ioc_extraction",
                "total_iocs": total_iocs,
                "by_type": ioc_summary,
                "files_processed": result.files_processed,
                "errors": result.errors[:20],
                "pattern_version": PATTERN_VERSION,
            },
            duration_seconds=round(duration, 3),
            files_processed=result.files_processed,
        )
        db.commit()

        logger.info(
            "IOC extraction for kit %s: %d IOCs from %d files",
            kit_id, total_iocs, result.files_processed,
        )
        return {
            **prev_result,
            "iocs_extracted": total_iocs,
            "ioc_summary": ioc_summary,
        }

    except SoftTimeLimitExceeded:
        duration = time.time() - start
        logger.warning(
            "IOC extraction for kit %s hit time limit after %.0fs, "
            "saving partial results",
            kit_id, duration,
        )
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.IOC_EXTRACTION,
                    result_data={
                        "step": "ioc_extraction",
                        "total_iocs": 0,
                        "by_type": {},
                        "files_processed": 0,
                        "errors": [f"Time limit exceeded after {duration:.0f}s"],
                        "timed_out": True,
                    },
                    duration_seconds=round(duration, 3),
                    files_processed=0,
                )
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {
            **prev_result,
            "iocs_extracted": 0,
            "ioc_summary": {},
            "timed_out": True,
        }

    except Exception as e:
        logger.exception("Error extracting IOCs from kit %s: %s", kit_id, e)
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# External JS Fetching
# ---------------------------------------------------------------------------


@celery_app.task(
    name="darla.tasks.analysis.fetch_external_js",
    bind=True,
    queue="analysis",
    soft_time_limit=120,
    time_limit=150,
)
def fetch_external_js(self, prev_result: dict) -> dict:
    """Fetch external JS sources referenced in <script src> tags.

    Follows external script references in rendered phishing pages to capture
    backend infrastructure (C2 URLs, Telegram exfil channels, credential
    relay endpoints) that live in external JS files.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    settings = get_settings()
    if not settings.external_js_fetch_enabled:
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from darla.analysis.js_fetcher import ExternalJSFetcher

        fetcher = ExternalJSFetcher(
            source_url=kit.source_url,
            max_depth=settings.external_js_fetch_max_depth,
            max_files=settings.external_js_fetch_max_files,
            max_size_kb=settings.external_js_fetch_max_size_kb,
            timeout=settings.external_js_fetch_timeout,
        )

        # For single-file kits, create an extract_dir so fetched JS has a home
        # and copy the main file in so fetch_from_directory can scan it.
        if not extract_dir and filepath:
            ext_path = Path(settings.kit_extract_dir) / kit_id
            ext_path.mkdir(parents=True, exist_ok=True)
            import shutil
            dest = ext_path / Path(filepath).name
            if not dest.exists():
                shutil.copy2(filepath, dest)
            extract_dir = str(ext_path)
            prev_result = {**prev_result, "extract_dir": extract_dir}

        if extract_dir:
            result = fetcher.fetch_from_directory(extract_dir)
        else:
            result = fetcher.fetch_from_file(filepath)

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.EXTERNAL_JS_FETCH,
            result_data={
                "files_fetched": result.files_fetched,
                "files_skipped_benign": result.files_skipped_benign,
                "files_skipped_error": result.files_skipped_error,
                "urls_discovered": result.urls_discovered[:50],
                "urls_fetched": result.urls_fetched[:50],
                "urls_skipped": result.urls_skipped[:50],
                "terminal_urls": result.terminal_urls[:50],
                "errors": result.errors[:20],
                "php_sources_found": result.php_sources_found,
            },
            duration_seconds=round(duration, 3),
            files_processed=result.files_fetched,
        )
        db.commit()

        if result.files_fetched or result.terminal_urls:
            logger.info(
                "External JS fetch for kit %s: %d fetched, %d skipped (benign), "
                "%d errors, %d PHP sources, %d terminal URLs",
                kit_id, result.files_fetched, result.files_skipped_benign,
                result.files_skipped_error, result.php_sources_found,
                len(result.terminal_urls),
            )

        return {
            **prev_result,
            "external_js_fetched": result.files_fetched,
            "external_js_urls": result.urls_fetched,
            "external_js_terminal_urls": result.terminal_urls,
        }

    except Exception as e:
        logger.exception("External JS fetch failed for kit %s", kit_id)
        duration = time.time() - start
        try:
            if kit:
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.EXTERNAL_JS_FETCH,
                    result_data={"error": str(e)},
                    duration_seconds=round(duration, 3),
                    error=str(e),
                )
                db.commit()
        except Exception:
            pass
        # Non-fatal: don't fail the pipeline if JS fetch fails
        return {**prev_result, "external_js_fetched": 0}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# YARA Scanning
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.analysis.yara_scan",
    bind=True,
    queue="analysis",
)
def yara_scan(self, prev_result: dict) -> dict:
    """Scan kit files against YARA rules for family/technique classification."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath")

    if not extract_dir and not filepath:
        return {**prev_result, "yara_matches": []}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "yara_matches": []}

        settings = get_settings()
        from darla.analysis.yara_scanner import get_cached_scanner

        scanner = get_cached_scanner(settings.yara_rules_dir)
        rules_count = scanner.rules_loaded

        if rules_count == 0:
            logger.debug("No YARA rules loaded, skipping scan for kit %s", kit_id)
            return {**prev_result, "yara_matches": []}

        # Always scan the raw downloaded file first (t4d rules match ZIP headers)
        result = scanner.scan_file(filepath) if filepath else None

        # Also scan extracted directory if available (our custom rules match PHP/HTML content)
        if extract_dir:
            dir_result = scanner.scan_directory(extract_dir)
            if result:
                result.matches.extend(dir_result.matches)
                result.files_scanned += dir_result.files_scanned
            else:
                result = dir_result

        if not result:
            return {**prev_result, "yara_matches": []}

        duration = time.time() - start

        match_data = [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": m.tags,
                "meta": m.meta,
                "strings": m.strings,
                "source_file": m.meta.get("source_file"),
            }
            for m in result.matches
        ]

        # Deduplicate by rule name — aggregate source_files and strings
        seen_rules: dict[str, dict] = {}
        unique_matches = []
        for m in match_data:
            if m["rule"] not in seen_rules:
                m["source_files"] = [m["source_file"]] if m["source_file"] else []
                seen_rules[m["rule"]] = m
                unique_matches.append(m)
            else:
                existing = seen_rules[m["rule"]]
                if m["source_file"] and m["source_file"] not in existing["source_files"]:
                    existing["source_files"].append(m["source_file"])
                # Merge unique strings
                existing_strings = set(existing.get("strings", []))
                for s in m.get("strings", []):
                    if s not in existing_strings:
                        existing["strings"].append(s)
                        existing_strings.add(s)

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.YARA_SCAN,
            result_data={
                "rules_loaded": rules_count,
                "matches": unique_matches,
                "match_count": len(unique_matches),
                "files_scanned": result.files_scanned,
                "error": result.error,
            },
            duration_seconds=round(duration, 3),
            files_processed=result.files_scanned,
        )
        db.commit()

        if unique_matches:
            rule_names = [m["rule"] for m in unique_matches]
            logger.info(
                "YARA scan for kit %s: %d rules matched (%s)",
                kit_id, len(unique_matches), ", ".join(rule_names[:5]),
            )
        else:
            logger.debug("YARA scan for kit %s: no matches", kit_id)

        return {
            **prev_result,
            "yara_matches": unique_matches,
        }

    except Exception as e:
        logger.exception("Error in YARA scan for kit %s: %s", kit_id, e)
        # YARA failure is non-fatal — don't fail the kit
        return {**prev_result, "yara_matches": []}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TLSH Similarity
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.analysis.compute_similarity",
    bind=True,
    queue="analysis",
)
def compute_similarity(self, prev_result: dict) -> dict:
    """Compare kit TLSH against recent analyzed kits for similarity clustering."""
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.tlsh:
            return {**prev_result, "similar_kits": []}

        from sqlalchemy import select

        from darla.analysis.hasher import compute_tlsh_distance

        # Compare against all analyzed kits with TLSH hashes
        candidates = db.scalars(
            select(Kit).where(
                Kit.tlsh.isnot(None),
                Kit.id != kit.id,
                Kit.status == KitStatus.ANALYZED,
            )
        ).all()

        threshold = 100
        similar = []
        for candidate in candidates:
            distance = compute_tlsh_distance(kit.tlsh, candidate.tlsh)
            if distance is not None and distance <= threshold:
                similar.append({
                    "kit_id": str(candidate.id),
                    "distance": distance,
                    "sha256": candidate.sha256,
                    "source_url": candidate.source_url,
                })

        similar.sort(key=lambda x: x["distance"])

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.SIMILARITY,
            result_data={
                "similar_kits": similar[:50],  # cap stored results
                "candidates_checked": len(candidates),
                "threshold": threshold,
                "matches_found": len(similar),
            },
            duration_seconds=round(duration, 3),
        )
        db.commit()

        if similar:
            logger.info(
                "Similarity for kit %s: %d similar kits (closest distance=%d)",
                kit_id, len(similar), similar[0]["distance"],
            )

        return {**prev_result, "similar_kits": similar[:10]}

    except Exception as e:
        logger.exception("Error computing similarity for kit %s: %s", kit_id, e)
        # Similarity failure is non-fatal
        return {**prev_result, "similar_kits": []}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Investigation Status
# ---------------------------------------------------------------------------


def _try_complete_investigation(db, investigation_id: uuid.UUID) -> None:
    """Mark investigation COMPLETED if all its kits are terminal."""
    from darla.models.investigation import Investigation, InvestigationStatus

    try:
        investigation = db.query(Investigation).filter(
            Investigation.id == investigation_id
        ).first()
        if not investigation:
            return
        if investigation.status == InvestigationStatus.COMPLETED:
            return

        # Count kits still in non-terminal states
        pending_count = db.query(Kit).filter(
            Kit.investigation_id == investigation_id,
            Kit.status.notin_([KitStatus.ANALYZED, KitStatus.FAILED]),
        ).count()

        if pending_count == 0:
            # Recompute counters from actual data — incremental updates
            # from chain.py/browser.py are fragile across reanalysis and
            # deletion.
            actual_count = db.query(Kit).filter(
                Kit.investigation_id == investigation_id,
            ).count()
            actual_depth = db.query(func.coalesce(func.max(Kit.chain_depth), 0)).filter(
                Kit.investigation_id == investigation_id,
            ).scalar()

            investigation.total_kits = actual_count
            investigation.total_depth_reached = actual_depth
            investigation.status = InvestigationStatus.COMPLETED
            db.commit()
            logger.info(
                "Investigation %s completed (%d kits, depth %d)",
                investigation_id, actual_count, actual_depth,
            )
        else:
            # Ensure it's marked IN_PROGRESS
            if investigation.status == InvestigationStatus.PENDING:
                investigation.status = InvestigationStatus.IN_PROGRESS
                db.commit()
    except Exception as e:
        logger.warning("Error checking investigation %s status: %s", investigation_id, e)
        with contextlib.suppress(Exception):
            db.rollback()


# ---------------------------------------------------------------------------
# Polymorphism Detection
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.analysis.detect_polymorphism",
    bind=True,
    queue="analysis",
)
def detect_polymorphism(self, prev_result: dict) -> dict:
    """Detect polymorphic kit variants among siblings sharing a relay domain.

    Groups siblings (same parent_kit_id) by relay domain and checks whether
    their TLSH distances fall in the polymorphism range (above dedup threshold
    but below unrelatedness ceiling).  If so, computes a structural diff to
    identify constant vs variable HTML elements.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    settings = get_settings()
    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.parent_kit_id:
            return {**prev_result, "polymorphism": None}

        # Gather all analysed/downloaded browser-render siblings
        siblings_q = db.query(Kit).filter(
            Kit.parent_kit_id == kit.parent_kit_id,
            Kit.discovery_method == "browser_render",
            Kit.status.in_([KitStatus.ANALYZED, KitStatus.DOWNLOADED]),
        ).all()

        if len(siblings_q) < settings.browser_polymorphism_min_variants:
            return {**prev_result, "polymorphism": None}

        from pathlib import Path as _Path

        sibling_data = [
            (str(s.id), s.tlsh, s.source_url, _Path(s.local_path) if s.local_path else None)
            for s in siblings_q
        ]

        from darla.analysis.polymorphism import detect_variants

        result = detect_variants(
            siblings=sibling_data,
            dedup_threshold=settings.browser_dedup_tlsh_threshold,
            max_distance=settings.browser_polymorphism_tlsh_max_distance,
            min_variants=settings.browser_polymorphism_min_variants,
        )

        duration = time.time() - start

        if result and result.is_polymorphic:
            from darla.models.analysis_result import AnalysisType

            result_data = {
                "is_polymorphic": True,
                "relay_domain": result.relay_domain,
                "variant_count": result.variant_count,
                "confidence": result.confidence,
                "sibling_kit_ids": result.sibling_kit_ids,
            }
            if result.structural_diff:
                result_data.update({
                    "structural_similarity": result.structural_diff.structural_similarity,
                    "constant_elements": result.structural_diff.constant_elements[:50],
                    "variable_elements": result.structural_diff.variable_elements[:50],
                    "constant_form_fields": result.structural_diff.constant_form_fields,
                    "variable_form_fields": result.structural_diff.variable_form_fields,
                    "token_patterns": result.structural_diff.token_patterns,
                })

            upsert_analysis_result(
                db,
                kit_id=kit.id,
                analysis_type=AnalysisType.POLYMORPHISM,
                result_data=result_data,
                duration_seconds=round(duration, 3),
            )
            db.commit()

            logger.info(
                "Polymorphism detected for kit %s: %d variants on %s "
                "(confidence=%.2f)",
                kit_id, result.variant_count, result.relay_domain,
                result.confidence,
            )
            return {**prev_result, "polymorphism": result_data}

        return {**prev_result, "polymorphism": None}

    except Exception as e:
        logger.warning("Polymorphism detection error for kit %s: %s", kit_id, e)
        return {**prev_result, "polymorphism": None}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Finalize Kit
# ---------------------------------------------------------------------------

@celery_app.task(
    name="darla.tasks.analysis.finalize_kit",
    bind=True,
    queue="analysis",
)
def finalize_kit(self, prev_result: dict) -> dict:
    """Mark kit as ANALYZED after the entire chain completes.

    This is the terminal task — sets the final status so the kit isn't
    marked done before QR decode, similarity, correlation, and chain
    crawl have run.  Also checks if all kits in the investigation are
    terminal (ANALYZED or FAILED) and updates investigation status.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        # Still check investigation completion for failed kits
        db = get_sync_db()
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit and kit.investigation_id:
                _try_complete_investigation(db, kit.investigation_id)
        except Exception:
            pass
        finally:
            db.close()
        return prev_result

    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return prev_result

        # Tier B: thin-results browser render safety net
        settings = get_settings()
        if (
            settings.browser_download_enabled
            and settings.browser_render_on_thin_results
            and not prev_result.get("browser_render_dispatched")
        ):
            iocs_extracted = prev_result.get("iocs_extracted", 0)
            yara_count = len(prev_result.get("yara_matches", []))
            is_thin = iocs_extracted <= 1 and yara_count == 0

            mime = kit.mime_type or ""
            is_html_like = mime in (
                "text/html", "application/octet-stream",
            ) or (
                kit.filename
                and kit.filename.endswith((".html", ".htm", ".bin"))
            )

            has_browser_child = db.query(Kit).filter(
                Kit.parent_kit_id == kit.id,
                Kit.discovery_method == "browser_render",
            ).first() is not None

            # Enforce depth limit — never dispatch browser_render beyond max_depth
            at_depth_limit = False
            if kit.investigation_id:
                from darla.models.investigation import Investigation

                investigation = db.query(Investigation).filter(
                    Investigation.id == kit.investigation_id
                ).first()
                if investigation:
                    max_depth = min(investigation.max_depth, settings.chain_max_depth)
                    if kit.chain_depth >= max_depth:
                        at_depth_limit = True

            if is_thin and is_html_like and not has_browser_child and not at_depth_limit:
                from darla.tasks.browser import (
                    browser_download_kit,
                    find_redundant_render_reason,
                    precreate_browser_render_child_kit,
                )

                # Same redundancy rule download_kit applied to Tier A —
                # a skipped redirect child is usually a thin JS loader,
                # so without this Tier B would re-dispatch the render.
                redundant = prev_result.get(
                    "browser_render_skipped",
                ) or find_redundant_render_reason(db, kit, None)
                if redundant:
                    child, skip_reason = None, redundant
                else:
                    child, skip_reason = precreate_browser_render_child_kit(
                        db, kit,
                    )
                if child is not None:
                    db.commit()
                    browser_download_kit.apply_async(
                        args=[kit_id, str(child.id), 0],
                    )
                    logger.info(
                        "Kit %s: thin results (iocs=%d, yara=%d), "
                        "dispatched browser render for child %s",
                        kit_id, iocs_extracted, yara_count, child.id,
                    )
                else:
                    logger.info(
                        "Kit %s: thin results, browser render skipped (%s)",
                        kit_id, skip_reason,
                    )

        kit.status = KitStatus.ANALYZED
        db.commit()

        logger.info("Kit %s finalized as ANALYZED", kit_id)

        # Check if all kits in the investigation are done
        if kit.investigation_id:
            _try_complete_investigation(db, kit.investigation_id)

        return {**prev_result, "status": "analyzed"}

    except Exception as e:
        logger.exception("Error finalizing kit %s: %s", kit_id, e)
        try:
            db.rollback()
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = f"Finalization error: {str(e)[:450]}"
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        return {**prev_result, "status": "failed", "error": str(e)}
    finally:
        db.close()
