"""Kit download Celery task."""

import logging
import uuid
from pathlib import Path

from darla.analysis.oauth_ioc import extract_oauth_iocs, is_oauth_authorize_url
from darla.analysis.redirect_tracker import RedirectTracker
from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.analysis_result import AnalysisType
from darla.models.kit import Kit, KitStatus
from darla.tasks.analysis import upsert_analysis_result
from darla.utils.egress import BLOCK_PREFIX as EGRESS_BLOCK_PREFIX
from darla.utils.http_client import download_file

logger = logging.getLogger(__name__)

# Markers of a Cloudflare Turnstile/challenge embedded in an HTTP 200
# body (Tier A.5 browser dispatch).
_CF_BODY_MARKERS = (
    "challenges.cloudflare.com/turnstile",
    "cf-turnstile",
    "data-sitekey",
)


def _dispatch_browser_render(db, parent_kit, kit_id: str, log_context: str) -> bool:
    """Pre-create a browser_render child kit and dispatch the task.

    Wraps the precreate-then-apply_async idiom used at every site that
    might need a browser render (Cloudflare retry, JS loader, OAuth
    authorize, 0-byte response, fast-path re-run).  Returns ``True`` if
    a task was dispatched, ``False`` if the precreate guards tripped
    (depth, max_variations, or per-investigation in-flight budget).

    The pre-created child kit id is passed to ``browser_download_kit``
    so that any task redelivery (worker SIGTERM, broker reconnect,
    etc.) sees the existing child past ``DOWNLOADING`` and exits no-op
    instead of starting a duplicate render — the orphan-child failure
    mode that drove the queue explosion before idempotency landed.
    """
    from darla.tasks.browser import (
        browser_download_kit,
        precreate_browser_render_child_kit,
    )

    child, skip_reason = precreate_browser_render_child_kit(db, parent_kit)
    if child is None:
        logger.info(
            "Kit %s: %s — browser render skipped (%s)",
            kit_id, log_context, skip_reason,
        )
        return False
    db.commit()
    browser_download_kit.apply_async(args=[kit_id, str(child.id), 0])
    logger.info(
        "Kit %s: %s — dispatched browser render for child %s",
        kit_id, log_context, child.id,
    )
    return True


@celery_app.task(
    name="darla.tasks.download.download_kit",
    bind=True,
    max_retries=1,
    default_retry_delay=30,
    queue="downloads",
)
def download_kit(
    self, kit_id: str, dispatch_followups: bool = True, force: bool = False,
) -> dict:
    """Download a phishing kit archive from its source URL.

    Updates the kit record with file metadata and transitions
    status to DOWNLOADED or FAILED.

    ``force`` (set on force-resubmit) bypasses the browser-render
    redundancy check, matching ``compute_hashes`` skipping SHA256 dedup.

    When ``dispatch_followups`` is ``False``, the task performs ONLY
    the download step — no browser-render dispatch, no OAuth
    browser-retry dispatch, no JS-loader fan-out.  Use this when
    re-running download_kit during pipeline development or surgical
    operator interventions to avoid generating cascade work.
    Investigation-mode IOC + redirect-chain side-effects still happen
    because they're part of *this* step, not follow-ups.
    """
    settings = get_settings()
    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            raise ValueError(f"Kit {kit_id} not found")

        # ------------------------------------------------------------------
        # OAuth authorize URLs (consent-phishing / AITM lures) — emit IOCs
        # from the URL *before* anything else, including the
        # "already have local file" fast-path.  Microsoft has been known
        # to disable malicious apps, and attacker AITM infra goes up and
        # down; neither should cost us the campaign fingerprint
        # (client_id, scope, state, victim email) which is recoverable
        # from the lure URL itself.  Running this up-front also means a
        # re-dispatch on an already-downloaded kit still refreshes the
        # IOCs (fields added to the extractor over time are picked up).
        # ------------------------------------------------------------------
        oauth_iocs = extract_oauth_iocs(kit.source_url)
        if oauth_iocs:
            try:
                upsert_analysis_result(
                    db,
                    kit_id=kit.id,
                    analysis_type=AnalysisType.OAUTH_AUTHORIZE,
                    result_data=oauth_iocs,
                )
                logger.info(
                    "Kit %s: recorded OAuth IOCs (client_id=%s, tenant=%s)",
                    kit_id,
                    oauth_iocs.get("client_id"),
                    oauth_iocs.get("tenant"),
                )
                # Funnel any victim/login-hint emails extracted from
                # the OAuth URL through the unified pipeline:
                #   * always emit an Indicator row (full search/
                #     correlation across all observed emails),
                #   * additionally promote to Victim entity when the
                #     domain matches the monitored allowlist.
                # Without this, OAuth-extracted emails were lost as
                # stand-alone IOCs (only buried inside the
                # OAUTH_AUTHORIZE result_data dict).
                from darla.models.indicator import Indicator, IndicatorType
                from darla.models.victim import VictimObservationSource
                from darla.services.victim_service import (
                    observe_victim_email,
                )

                _email_sources = [
                    (
                        oauth_iocs.get("victim_email"),
                        "oauth_state",
                        VictimObservationSource.OAUTH_STATE,
                    ),
                    (
                        oauth_iocs.get("login_hint"),
                        "oauth_login_hint",
                        VictimObservationSource.OAUTH_LOGIN_HINT,
                    ),
                ]
                for email_val, ioc_context, victim_source in _email_sources:
                    if not email_val or "@" not in email_val:
                        continue
                    db.add(Indicator(
                        type=IndicatorType.EMAIL,
                        value=email_val.lower(),
                        context=ioc_context,
                        source_file=kit.source_url[:500],
                        confidence=85,
                        kit_id=kit.id,
                    ))
                    observe_victim_email(
                        db, kit.id, email_val, victim_source,
                    )
            except Exception as exc:
                logger.warning(
                    "Kit %s: failed to persist OAuth IOCs: %s", kit_id, exc,
                )

        # If file already exists on disk (e.g. manual upload or prior
        # successful download), skip re-download but still dispatch the
        # browser render for OAuth authorize URLs — httpx can't follow
        # the JS handoff to login.live.com → attacker redirect_uri, so
        # without the browser path we'd miss the AITM proxy content.
        if kit.local_path and Path(kit.local_path).exists():
            filepath = Path(kit.local_path)
            kit.file_size = filepath.stat().st_size
            kit.filename = filepath.name
            kit.status = KitStatus.DOWNLOADED
            kit.error_message = None  # clear stale error from prior failed run
            suffix = filepath.suffix.lower()
            mime_map = {
                ".zip": "application/zip",
                ".gz": "application/gzip",
                ".tar": "application/x-tar",
                ".rar": "application/x-rar-compressed",
                ".php": "application/x-php",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".bmp": "image/bmp",
                ".webp": "image/webp",
                ".eml": "message/rfc822",
            }
            kit.mime_type = mime_map.get(suffix, "application/octet-stream")
            db.commit()
            logger.info("Kit %s already has local file, skipping download", kit_id)

            result: dict = {
                "kit_id": kit_id,
                "status": "downloaded",
                "filepath": kit.local_path,
                "file_size": kit.file_size,
            }
            if (
                dispatch_followups
                and settings.browser_download_enabled
                and is_oauth_authorize_url(kit.source_url)
            ) and _dispatch_browser_render(
                db, kit, kit_id, "OAuth authorize URL (fast-path)",
            ):
                result["browser_render_dispatched"] = True
            return result

        kit.status = KitStatus.DOWNLOADING
        db.commit()

        logger.info("Downloading kit %s from %s", kit_id, kit.source_url)

        # Create per-kit download directory
        download_dir = Path(settings.kit_download_dir) / kit_id
        download_dir.mkdir(parents=True, exist_ok=True)

        redirect_chain_data = None

        # Investigation-mode kits use redirect tracking to capture the full chain
        if kit.investigation_id:
            tracker = RedirectTracker()
            filepath, reason, redirect_chain = tracker.download_with_redirects(
                kit.source_url,
                str(download_dir),
                max_size_mb=settings.max_kit_size_mb,
            )
            # Always persist the chain on investigation-mode runs — even
            # a zero-hop result is authoritative data (replaces any stale
            # chain from a previous run against different code).  This
            # matters specifically for re-runs after redirect-extractor
            # fixes: a now-correct "no JS redirect to follow" outcome
            # would otherwise be masked by the old row claiming we
            # followed a dead-end.
            redirect_chain_data = redirect_chain.to_dict()
            upsert_analysis_result(
                db,
                kit_id=kit.id,
                analysis_type=AnalysisType.REDIRECT_CHAIN,
                result_data=redirect_chain_data,
            )
            if redirect_chain.total_redirects == 0:
                redirect_chain_data = None  # don't echo into result dict
        else:
            filepath, reason = download_file(
                kit.source_url,
                str(download_dir),
                max_size_mb=settings.max_kit_size_mb,
            )

        # Dispatch to browser worker for Cloudflare-protected pages and for
        # OAuth authorize URLs (attacker-registered apps may be dead at the
        # IdP but the stored ``source_url`` is often served via a
        # browser-only JS handoff — we still want Camoufox to try it before
        # declaring FAILED).
        if (
            not filepath
            and dispatch_followups
            and settings.browser_download_enabled
        ):
            from darla.analysis.browser_downloader import (
                is_cloudflare_challenge,
            )

            # Never hand an egress-blocked destination to the browser —
            # Camoufox isn't behind the connect-time guard.
            should_browser_retry = not reason.startswith(EGRESS_BLOCK_PREFIX) and (
                is_cloudflare_challenge(reason)
                or is_oauth_authorize_url(kit.source_url)
            )
            if should_browser_retry and _dispatch_browser_render(
                db, kit, kit_id,
                f"httpx failed ({reason}), retrying via browser",
            ):
                result = {
                    "kit_id": kit_id,
                    "status": "browser_retry",
                }
                if redirect_chain_data:
                    result["redirect_chain"] = redirect_chain_data
                return result

        if not filepath:
            kit.status = KitStatus.FAILED
            kit.error_message = reason
            db.commit()
            result = {"kit_id": kit_id, "status": "failed", "error": reason}
            if redirect_chain_data:
                result["redirect_chain"] = redirect_chain_data
            return result

        # Update kit metadata
        kit.local_path = str(filepath)
        kit.filename = filepath.name
        kit.file_size = filepath.stat().st_size

        # Treat 0-byte responses as download failures — the server
        # returned nothing (common with bot-gated pages).  Dispatch to
        # browser worker if enabled, otherwise mark FAILED.
        if kit.file_size == 0:
            if dispatch_followups and settings.browser_download_enabled:
                if _dispatch_browser_render(
                    db, kit, kit_id, "0-byte response",
                ):
                    return {
                        "kit_id": kit_id,
                        "status": "browser_retry",
                    }
                # If precreate guard tripped, fall through to FAILED.
                kit.status = KitStatus.FAILED
                kit.error_message = (
                    "Empty response (0 bytes); browser retry suppressed by guard"
                )
                db.commit()
                return {
                    "kit_id": kit_id,
                    "status": "failed",
                    "error": "empty_response",
                }
            else:
                kit.status = KitStatus.FAILED
                kit.error_message = "Empty response (0 bytes)"
                db.commit()
                return {
                    "kit_id": kit_id,
                    "status": "failed",
                    "error": "empty_response",
                }

        kit.status = KitStatus.DOWNLOADED
        # Clear any stale error from a prior failed run — this kit is
        # live now, and a lingering "HTTP 404" next to a DOWNLOADED
        # status misleads operators (see the Azure OAuth re-run case).
        kit.error_message = None

        # Guess MIME type
        suffix = filepath.suffix.lower()
        mime_map = {
            ".zip": "application/zip",
            ".gz": "application/gzip",
            ".tar": "application/x-tar",
            ".rar": "application/x-rar-compressed",
            ".php": "application/x-php",
            ".eml": "message/rfc822",
        }
        kit.mime_type = mime_map.get(suffix, "application/octet-stream")
        db.commit()

        # If the redirect tracker wrote a stage manifest (JS/meta hops),
        # segment the chain into stages for the flow view.  Own
        # transaction, best-effort — never fails the download.
        if kit.investigation_id and redirect_chain_data:
            try:
                from darla.services.stage_service import build_and_store_stages

                build_and_store_stages(db, kit, download_dir)
                db.commit()
            except Exception as stage_err:
                logger.debug(
                    "Kit %s: root stage segmentation failed: %s",
                    kit_id, stage_err,
                )
                import contextlib as _cl
                with _cl.suppress(Exception):
                    db.rollback()

        logger.info(
            "Kit %s downloaded: %s (%d bytes)",
            kit_id, filepath.name, kit.file_size,
        )
        result = {
            "kit_id": kit_id,
            "status": "downloaded",
            "filepath": str(filepath),
            "file_size": kit.file_size,
        }
        if redirect_chain_data:
            result["redirect_chain"] = redirect_chain_data
            # Only the final destination becomes a child kit — intermediate
            # hops are recorded in the redirect_chain analysis result but
            # don't spawn their own kits.
            final_url = redirect_chain_data.get("final_url", "")
            if final_url and final_url != kit.source_url:
                result["redirect_urls"] = [final_url]
            else:
                result["redirect_urls"] = []

        # The Tier A dispatches below run before compute_hashes can dedup
        # this kit, and a queued render can't be recalled.  Skip them when
        # the render would provably duplicate work already in the
        # investigation (see find_redundant_render_reason).
        render_redundant: str | None = None
        if (
            dispatch_followups
            and settings.browser_download_enabled
            and not force
            and kit.investigation_id
        ):
            import hashlib

            from darla.tasks.browser import find_redundant_render_reason

            render_redundant = find_redundant_render_reason(
                db, kit, hashlib.sha256(filepath.read_bytes()).hexdigest(),
            )
            if render_redundant:
                result["browser_render_skipped"] = render_redundant
                logger.info(
                    "Kit %s: browser render skipped (%s)",
                    kit_id, render_redundant,
                )

        # Tier A: JS loader / embedded challenge detection
        # → dispatch browser render in parallel with analysis chain
        if (
            dispatch_followups
            and settings.browser_download_enabled
            and not render_redundant
        ):
            is_html_like = (
                suffix in (".html", ".htm", ".bin", "")
                or kit.mime_type == "application/octet-stream"
            )
            if is_html_like:
                dispatch_reason: str | None = None

                from darla.analysis.browser_downloader import is_js_loader

                if is_js_loader(filepath):
                    dispatch_reason = "JS loader detected"

                # Tier A.5: Cloudflare Turnstile/challenge in HTTP 200
                # body — httpx got the page but it needs a browser to
                # solve the embedded challenge.
                if dispatch_reason is None:
                    try:
                        body = filepath.read_text(
                            encoding="utf-8", errors="ignore",
                        )[:100_000]
                        if any(m in body for m in _CF_BODY_MARKERS):
                            dispatch_reason = (
                                "Cloudflare Turnstile in response body"
                            )
                    except Exception:
                        pass

                if dispatch_reason is not None and _dispatch_browser_render(
                    db, kit, kit_id, dispatch_reason,
                ):
                    result["browser_render_dispatched"] = True

        # Tier A.6: OAuth authorize URL — the body we downloaded is an
        # IdP handoff scaffold (Microsoft's 200 with JS that hands off to
        # login.live.com, which then 302s to the attacker's registered
        # redirect_uri and into an AITM proxy).  Pure-HTTP can't follow
        # that chain — the JS handoff isn't a standard `location.replace`
        # we can regex.  Always dispatch browser render for these URLs.
        if (
            dispatch_followups
            and settings.browser_download_enabled
            and is_oauth_authorize_url(kit.source_url)
            and not result.get("browser_render_dispatched")
            and not render_redundant
        ) and _dispatch_browser_render(
            db, kit, kit_id, "OAuth authorize URL",
        ):
            result["browser_render_dispatched"] = True

        return result

    except Exception as e:
        logger.exception("Error downloading kit %s: %s", kit_id, e)
        try:
            kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
            if kit:
                kit.status = KitStatus.FAILED
                kit.error_message = str(e)[:500]
                db.commit()
        except Exception as exc:
            logger.debug("Failed to mark kit as FAILED during error handling: %s", exc)
        raise self.retry(exc=e) from e

    finally:
        db.close()
