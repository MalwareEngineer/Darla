"""Chain crawling tasks — EML parsing, QR decoding, and link-following."""

import logging
import re
import time
import uuid
from pathlib import Path

from celery.exceptions import SoftTimeLimitExceeded

from darla.celery_app import celery_app
from darla.config import get_settings
from darla.database import get_sync_db
from darla.models.analysis_result import AnalysisType
from darla.models.kit import Kit
from darla.tasks.analysis import upsert_analysis_result

logger = logging.getLogger(__name__)

# Image extensions to scan for QR codes
IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
})


@celery_app.task(
    name="darla.tasks.chain.parse_eml",
    bind=True,
    queue="analysis",
    soft_time_limit=120,
    time_limit=150,
)
def parse_eml(self, prev_result: dict) -> dict:
    """Parse .eml file: extract headers, body, links, attachments, images.

    No-op if the downloaded file is not an .eml file.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    filepath = prev_result.get("filepath", "")
    if not filepath or not filepath.lower().endswith(".eml"):
        return prev_result

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "status": "failed", "error": "kit_not_found"}

        from darla.analysis.eml_parser import EMLParser

        parser = EMLParser()
        result = parser.parse(filepath)

        settings = get_settings()
        extract_dir = str(Path(settings.kit_extract_dir) / kit_id)

        # Save attachments and embedded images to disk for downstream tasks
        saved_files = parser.save_attachments(result, extract_dir)
        # Nested EMLs are saved under a subdir so they're not rescanned as
        # attachments of the outer kit — each becomes its own child kit.
        saved_nested = parser.save_nested_emls(result, extract_dir)

        duration = time.time() - start

        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.EML_PARSE,
            result_data={
                "headers": result.headers,
                "links_found": len(result.links),
                "attachments": len(result.attachments),
                "embedded_images": len(result.embedded_images),
                "nested_emls": len(result.nested_emls),
                "has_html_body": result.body_html is not None,
                "has_text_body": result.body_text is not None,
                "saved_files": len(saved_files),
                "errors": result.errors[:20],
            },
            duration_seconds=round(duration, 3),
            files_processed=len(result.attachments) + len(result.embedded_images),
        )

        # Extract IOCs from EML headers (sender domain, Return-Path, IPs)
        from darla.analysis.patterns import BENIGN_DOMAINS, extract_root_domain
        from darla.models.indicator import Indicator, IndicatorType

        eml_iocs_added = 0

        # Guard: skip if EML header IOCs already exist (reanalysis / retry)
        _has_eml_iocs = db.query(Indicator.id).filter(
            Indicator.kit_id == kit.id,
            Indicator.context.like("eml_%"),
        ).first()

        if not _has_eml_iocs:
            sender_domain = None

            # Sender domain from From header
            from_header = result.headers.get("From", "")
            email_match = re.search(r"<([^>]+@([^>]+))>", from_header)
            if not email_match:
                email_match = re.search(r"([^\s]+@([^\s>]+))", from_header)
            if email_match:
                sender_email = email_match.group(1).lower()
                sender_domain = email_match.group(2).lower()
                sender_root = extract_root_domain(sender_domain)
                if sender_root not in BENIGN_DOMAINS:
                    db.add(Indicator(
                        type=IndicatorType.EMAIL,
                        value=sender_email,
                        context="eml_from_header",
                        source_file=filepath,
                        confidence=90,
                        kit_id=kit.id,
                    ))
                    db.add(Indicator(
                        type=IndicatorType.DOMAIN,
                        value=sender_domain,
                        context="eml_sender_domain",
                        source_file=filepath,
                        confidence=90,
                        kit_id=kit.id,
                    ))
                    eml_iocs_added += 2

            # Return-Path domain
            return_path = result.headers.get("Return-Path", "")
            rp_match = re.search(r"@([^\s>]+)", return_path)
            if rp_match:
                rp_domain = rp_match.group(1).lower()
                rp_root = extract_root_domain(rp_domain)
                if rp_root not in BENIGN_DOMAINS and rp_domain != sender_domain:
                    db.add(Indicator(
                        type=IndicatorType.DOMAIN,
                        value=rp_domain,
                        context="eml_return_path",
                        source_file=filepath,
                        confidence=85,
                        kit_id=kit.id,
                    ))
                    eml_iocs_added += 1

            # Recipient addresses (To/Cc/Bcc) — emit Indicator rows
            # for ALL recipients (full IOC visibility, even on
            # non-monitored domains where attackers test their own
            # infrastructure) and route through the unified victim
            # pipeline so monitored-domain employees are promoted to
            # PhishPrint Victim entities with the correct source
            # channel.
            from darla.models.victim import VictimObservationSource
            from darla.services.victim_service import observe_victim_email

            _recipient_headers = [
                ("To", "eml_to_header", VictimObservationSource.EML_TO),
                ("Cc", "eml_cc_header", VictimObservationSource.EML_CC),
                ("Bcc", "eml_bcc_header", VictimObservationSource.EML_BCC),
            ]
            for header_name, ioc_context, victim_source in _recipient_headers:
                header_val = result.headers.get(header_name, "")
                if not header_val:
                    continue
                # ``getaddresses`` handles "Name <addr>" and comma-
                # separated lists correctly — including obfuscated
                # forms attackers occasionally use in lure headers.
                import email.utils as _eu
                for _name, addr in _eu.getaddresses([header_val]):
                    if not addr or "@" not in addr:
                        continue
                    addr_lower = addr.strip().lower()
                    db.add(Indicator(
                        type=IndicatorType.EMAIL,
                        value=addr_lower,
                        context=ioc_context,
                        source_file=filepath,
                        confidence=90,
                        kit_id=kit.id,
                    ))
                    observe_victim_email(
                        db, kit.id, addr_lower, victim_source,
                    )
                    eml_iocs_added += 1

            # Sending IPs from Received headers
            received_all = result.headers.get("Received-All", "")
            ip_re = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
            seen_ips = set()
            for ip in ip_re.findall(received_all):
                if ip in seen_ips:
                    continue
                # Skip private/internal IPs
                if ip.startswith(("10.", "192.168.", "127.", "172.16.",
                                  "172.17.", "172.18.", "172.19.",
                                  "172.2", "172.30.", "172.31.")):
                    continue
                seen_ips.add(ip)
                db.add(Indicator(
                    type=IndicatorType.IP_ADDRESS,
                    value=ip,
                    context="eml_received_header",
                    source_file=filepath,
                    confidence=80,
                    kit_id=kit.id,
                ))
                eml_iocs_added += 1

        if eml_iocs_added:
            logger.info(
                "EML header IOCs for kit %s: %d indicators",
                kit_id, eml_iocs_added,
            )

        # SVG inspection — detect script-bearing SVGs, emit URL IOCs, and
        # leave the SVG in extract_dir so fetch_external_js picks it up via
        # the expanded SCANNABLE_EXTENSIONS set.
        svg_inspected = 0
        svg_script_bearing = 0
        svg_urls_found = 0
        for fpath in saved_files:
            p = Path(fpath)
            # Strip attacker-appended trailing dots/spaces before suffix check
            # (e.g. "ATT021.svg.." must still be detected as SVG).
            _suffix = Path(p.name.rstrip(". ")).suffix.lower()
            if _suffix != ".svg":
                continue
            try:
                from darla.analysis.svg_inspector import inspect_file as svg_inspect

                svg_result = svg_inspect(p)
            except Exception as svg_err:
                logger.debug("SVG inspect failed for %s: %s", p, svg_err)
                continue

            svg_inspected += 1
            if not svg_result.is_suspicious and not svg_result.all_urls:
                continue
            if svg_result.has_script:
                svg_script_bearing += 1

            for url in svg_result.all_urls:
                svg_urls_found += 1
                db.add(Indicator(
                    type=IndicatorType.URL,
                    value=url[:500],
                    context="svg_script_reference",
                    source_file=str(p),
                    confidence=85,
                    kit_id=kit.id,
                ))

        if svg_inspected:
            logger.info(
                "SVG inspection for kit %s: %d inspected, %d script-bearing, "
                "%d URLs extracted",
                kit_id, svg_inspected, svg_script_bearing, svg_urls_found,
            )

        db.commit()

        # Nested EML spawning — each message/rfc822 attachment becomes its
        # own child kit so it gets independent analysis (envelope IOCs,
        # attachment extraction, its own SVG / JS loader / QR pipeline).
        nested_spawned: list[str] = []
        if saved_nested:
            from darla.models.kit import Kit as KitModel
            from darla.models.kit import KitStatus

            for _nested, nested_path in saved_nested:
                p = Path(nested_path)
                existing = db.query(KitModel).filter(
                    KitModel.parent_kit_id == kit.id,
                    KitModel.local_path == str(p),
                ).first()
                if existing:
                    logger.info(
                        "Kit %s: nested EML %s already spawned (%s), skipping",
                        kit_id, p.name, existing.id,
                    )
                    continue

                file_url = p.resolve().as_uri()
                child = KitModel(
                    source_url=file_url,
                    source_feed=kit.source_feed,
                    status=KitStatus.DOWNLOADED,
                    parent_kit_id=kit.id,
                    investigation_id=kit.investigation_id,
                    chain_depth=kit.chain_depth + 1,
                    discovery_method="nested_eml",
                    local_path=str(p),
                    filename=p.name,
                    file_size=p.stat().st_size,
                    mime_type="message/rfc822",
                )
                db.add(child)
                db.flush()

                if kit.investigation_id:
                    from darla.models.investigation import Investigation

                    inv = db.query(Investigation).filter(
                        Investigation.id == kit.investigation_id
                    ).first()
                    if inv:
                        inv.total_kits += 1

                db.commit()

                from darla.tasks.analysis import build_post_download_chain

                child_result = {
                    "kit_id": str(child.id),
                    "status": "downloaded",
                    "filepath": str(p),
                    "file_size": child.file_size,
                }
                build_post_download_chain(child_result).apply_async()
                nested_spawned.append(str(child.id))

            if nested_spawned:
                logger.info(
                    "Kit %s: spawned %d nested EML child kit(s)",
                    kit_id, len(nested_spawned),
                )

        # JS loader detection on extracted HTML attachments
        browser_renders_dispatched = []
        if settings.browser_download_enabled and saved_files:
            from darla.analysis.browser_downloader import is_js_loader
            from darla.models.kit import Kit as KitModel
            from darla.models.kit import KitStatus

            for fpath in saved_files:
                p = Path(fpath)
                if p.suffix.lower() not in (".html", ".htm"):
                    continue
                if not is_js_loader(p):
                    continue

                # Guard: skip if a child already exists for this file
                # (prevents duplicates on reanalysis or task retry)
                existing = db.query(KitModel).filter(
                    KitModel.parent_kit_id == kit.id,
                    KitModel.local_path == str(p),
                ).first()
                if existing:
                    logger.info(
                        "Kit %s: child for %s already exists (%s), skipping",
                        kit_id, p.name, existing.id,
                    )
                    continue

                logger.info(
                    "Kit %s: EML attachment %s is JS loader, "
                    "dispatching browser render",
                    kit_id, p.name,
                )
                # Use file:// URL so browser_download_kit opens the
                # local JS loader in the browser, follows the redirect,
                # and captures the actual phishing page.
                file_url = p.resolve().as_uri()
                child = KitModel(
                    source_url=file_url,
                    source_feed=kit.source_feed,
                    status=KitStatus.DOWNLOADED,
                    parent_kit_id=kit.id,
                    investigation_id=kit.investigation_id,
                    chain_depth=kit.chain_depth + 1,
                    discovery_method="eml_attachment",
                    local_path=str(p),
                    filename=p.name,
                    file_size=p.stat().st_size,
                    mime_type="text/html",
                )
                db.add(child)
                db.flush()

                if kit.investigation_id:
                    from darla.models.investigation import Investigation

                    inv = db.query(Investigation).filter(
                        Investigation.id == kit.investigation_id
                    ).first()
                    if inv:
                        inv.total_kits += 1

                db.commit()

                # Dispatch analysis chain for the JS loader itself
                from darla.tasks.analysis import build_post_download_chain

                child_result = {
                    "kit_id": str(child.id),
                    "status": "downloaded",
                    "filepath": str(p),
                    "file_size": child.file_size,
                }
                build_post_download_chain(child_result).apply_async()

                # Also dispatch browser render to follow the JS redirect.
                # Pre-create the grandchild kit so the dispatched task is
                # idempotent on redelivery.
                from darla.tasks.browser import (
                    browser_download_kit,
                    precreate_browser_render_child_kit,
                )

                grandchild, skip_reason = (
                    precreate_browser_render_child_kit(db, child)
                )
                if grandchild is not None:
                    db.commit()
                    browser_download_kit.apply_async(
                        args=[str(child.id), str(grandchild.id), 0],
                    )
                    browser_renders_dispatched.append(str(child.id))
                else:
                    logger.info(
                        "EML JS-loader kit %s: browser render skipped (%s)",
                        child.id, skip_reason,
                    )

        logger.info(
            "EML parse for kit %s: %d links, %d attachments, %d images, "
            "%d nested EMLs%s",
            kit_id, len(result.links), len(result.attachments),
            len(result.embedded_images), len(result.nested_emls),
            f", {len(browser_renders_dispatched)} browser renders dispatched"
            if browser_renders_dispatched else "",
        )

        return {
            **prev_result,
            "eml_links": result.links,
            "eml_headers": result.headers,
            "eml_attachment_count": len(result.attachments),
            "eml_image_count": len(result.embedded_images),
            "eml_nested_emls": len(result.nested_emls),
            "eml_nested_spawned": nested_spawned,
            "eml_browser_renders": browser_renders_dispatched,
            # If we extracted attachments, set extract_dir for downstream
            "extract_dir": extract_dir if saved_files else prev_result.get("extract_dir"),
            "extracted": True if saved_files else prev_result.get("extracted", False),
        }

    except SoftTimeLimitExceeded:
        logger.warning("EML parse for kit %s hit time limit", kit_id)
        return prev_result
    except Exception as e:
        logger.exception("Error parsing EML for kit %s: %s", kit_id, e)
        return prev_result  # Non-fatal: don't fail the whole chain
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.chain.decode_qr_codes",
    bind=True,
    queue="analysis",
    soft_time_limit=120,
    time_limit=150,
)
def decode_qr_codes(self, prev_result: dict) -> dict:
    """Scan images in kit directory for QR codes and extract URLs.

    Scans both extracted archive images and EML embedded images.
    Gracefully degrades if pyzbar is not installed.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    extract_dir = prev_result.get("extract_dir")
    filepath = prev_result.get("filepath", "")

    # No images to scan if no extraction and not an image file
    if not extract_dir and not any(filepath.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
        return {**prev_result, "qr_urls": []}

    try:
        from darla.analysis.qr_decoder import QRDecoder
    except ImportError:
        logger.info("pyzbar not installed, skipping QR decode for kit %s", kit_id)
        return {**prev_result, "qr_urls": []}

    db = get_sync_db()
    start = time.time()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit:
            return {**prev_result, "qr_urls": []}

        decoder = QRDecoder()

        if extract_dir:
            result = decoder.scan_directory(extract_dir)
        else:
            result = decoder.decode_file(filepath)

        duration = time.time() - start

        if result.qr_count > 0:
            upsert_analysis_result(
                db,
                kit_id=kit.id,
                analysis_type=AnalysisType.QR_DECODE,
                result_data={
                    "qr_codes_found": result.qr_count,
                    "urls_decoded": result.urls,
                    "errors": result.errors[:20],
                },
                duration_seconds=round(duration, 3),
            )
            db.commit()

        logger.info(
            "QR decode for kit %s: %d QR codes, %d URLs",
            kit_id, result.qr_count, len(result.urls),
        )

        return {
            **prev_result,
            "qr_urls": result.urls,
        }

    except SoftTimeLimitExceeded:
        logger.warning("QR decode for kit %s hit time limit", kit_id)
        return {**prev_result, "qr_urls": []}
    except Exception as e:
        logger.exception("Error decoding QR for kit %s: %s", kit_id, e)
        return {**prev_result, "qr_urls": []}
    finally:
        db.close()


@celery_app.task(
    name="darla.tasks.chain.crawl_chain",
    bind=True,
    queue="analysis",
    soft_time_limit=300,
    time_limit=330,
)
def crawl_chain(self, prev_result: dict) -> dict:
    """Create child kits from actual HTTP redirects in the crawl chain.

    Only fires for kits that belong to an investigation (chain mode).
    Child kits are created ONLY from redirect URLs (HTTP 30x hops) — URLs
    extracted from page source (C2, EML links, QR codes) remain as indicators
    on the parent kit.
    """
    kit_id = prev_result["kit_id"]
    if prev_result.get("status") == "failed":
        return prev_result

    db = get_sync_db()

    try:
        kit = db.query(Kit).filter(Kit.id == uuid.UUID(kit_id)).first()
        if not kit or not kit.investigation_id:
            return prev_result

        # Browser-render kits re-download the same URL with a real browser.
        # Their redirect chain duplicates the parent's — skip child spawning.
        if kit.discovery_method == "browser_render":
            logger.info(
                "Kit %s is a browser_render child, skipping chain crawl",
                kit_id,
            )
            return {**prev_result, "chain_skipped": "browser_render"}

        from darla.models.investigation import Investigation

        investigation = db.query(Investigation).filter(
            Investigation.id == kit.investigation_id
        ).first()
        if not investigation:
            return prev_result

        # Depth check
        settings = get_settings()
        max_depth = min(investigation.max_depth, settings.chain_max_depth)
        if kit.chain_depth >= max_depth:
            logger.info(
                "Kit %s at max depth %d, not crawling further",
                kit_id, kit.chain_depth,
            )
            return {**prev_result, "chain_skipped": "max_depth"}

        if not settings.chain_enabled:
            return {**prev_result, "chain_skipped": "disabled"}

        # Child kits are created ONLY from navigation events:
        #  - HTTP redirects (30x hops in the download chain)
        #  - EML links (URLs a victim would click in the email)
        #  - QR code URLs (encoded destination the victim scans)
        # URLs extracted from page source (C2, JS refs, etc.) stay as
        # indicators on the parent kit — no child kit explosion.
        from darla.analysis.link_scorer import ScoredLink

        scored: list[ScoredLink] = []
        seen = set()

        def _add(url: str, source: str, score: float, reason: str) -> None:
            # Reject non-HTTP URLs and bare paths like "/"
            if not url or not url.startswith(("http://", "https://")):
                return
            if url in seen or url == kit.source_url:
                return
            seen.add(url)
            scored.append(ScoredLink(
                url=url, score=score, source=source, reasons=[reason],
            ))

        for url in prev_result.get("redirect_urls", []):
            _add(url, "redirect", 0.9, "http_redirect")
        for url in prev_result.get("eml_links", []):
            _add(url, "eml_link", 0.8, "email_link")
        for url in prev_result.get("qr_urls", []):
            _add(url, "qr_code", 0.85, "qr_code_url")
        # Terminal landing pages discovered by the external-JS fetch chain.
        # Intermediate JS hops stay as content on the parent kit; the final
        # HTML navigation target becomes its own child for browser render.
        for url in prev_result.get("external_js_terminal_urls", []):
            _add(url, "svg_chain_terminal", 0.85, "svg_chain_terminal")

        if not scored:
            return {**prev_result, "children_spawned": 0}

        max_children = settings.chain_max_children_per_kit
        to_follow = scored[:max_children]

        # Submit child kits
        from darla.analysis.chain_crawler import ChainCrawler

        crawler = ChainCrawler(db)
        child_ids = crawler.submit_child_kits(
            parent_kit_id=kit.id,
            investigation_id=investigation.id,
            scored_links=to_follow,
            current_depth=kit.chain_depth,
        )

        # Update investigation stats
        investigation.total_kits += len(child_ids)
        new_depth = kit.chain_depth + 1
        if new_depth > investigation.total_depth_reached:
            investigation.total_depth_reached = new_depth

        # Record link scoring results
        start = time.time()
        upsert_analysis_result(
            db,
            kit_id=kit.id,
            analysis_type=AnalysisType.LINK_SCORE,
            result_data={
                "navigation_urls_found": len(scored),
                "children_spawned": len(child_ids),
                "scored_links": [
                    {"url": s.url, "score": s.score, "reasons": s.reasons, "source": s.source}
                    for s in scored[:50]
                ],
            },
            duration_seconds=round(time.time() - start, 3),
        )
        db.commit()

        logger.info(
            "Chain crawl for kit %s: %d links scored, %d children spawned",
            kit_id, len(scored), len(child_ids),
        )

        return {
            **prev_result,
            "children_spawned": len(child_ids),
            "child_kit_ids": [str(cid) for cid in child_ids],
        }

    except SoftTimeLimitExceeded:
        logger.warning("Chain crawl for kit %s hit time limit", kit_id)
        return prev_result
    except Exception as e:
        logger.exception("Error in chain crawl for kit %s: %s", kit_id, e)
        return prev_result
    finally:
        db.close()
