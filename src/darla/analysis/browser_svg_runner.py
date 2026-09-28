"""Active SVG execution harness — detonate attached SVG files in Camoufox.

Phishing SVG attachments frequently contain JavaScript that, on render,
dynamically fetches a remote loader keyed by the recipient's email. Because
``window.dawa`` / ``window.location.search`` / similar runtime state is
unavailable at static-analysis time, the real attacker infrastructure is
unreachable from ``deobfuscator.py``.

This module renders the SVG in a real browser with JavaScript enabled,
intercepts every outbound request, and returns the captured URLs.
Terminal (landing-page-class) URLs are surfaced separately so the chain
crawler can spawn child kits without a second EML submission.

Safety: this intentionally *does* let the payload reach the network — the
whole point is attacker infra capture. The caller (``execute_svgs_active``
task) is gated behind ``settings.svg_active_exec_enabled`` and a per-kit
budget, so the detonation only runs on kits already accepted into the
analysis pipeline.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Content-type prefixes we'll treat as "a landing page" (potential credential
# harvester). Anything else that a captured request points at is recorded but
# not auto-promoted to a terminal URL.
_LANDING_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml",
)

# Hosts that serve HTML gates but are never the phishing payload itself.
# Turnstile / hCaptcha interstitials load in iframes during the loader's
# bot-check phase; promoting them to terminal URLs spawns wasted child kits
# that just re-render the same challenge page across polymorphism generations.
#
# Scope is intentionally narrow — we only suppress *first-party* gate infra
# (Cloudflare's own ``challenges.cloudflare.com`` domain, hCaptcha's own
# domains).  We do NOT suppress arbitrary Cloudflare-fronted domains because
# legitimate phishing pages often sit behind Cloudflare proxies.
#
# Matched by exact hostname or hostname suffix (covers ``*.hcaptcha.com``).
_SUPPRESS_TERMINAL_HOSTS: frozenset[str] = frozenset({
    "challenges.cloudflare.com",
    "challenges.cloudflareaccess.com",
    "hcaptcha.com",
    "newassets.hcaptcha.com",
})

# reCAPTCHA lives at ``www.google.com/recaptcha/...`` — we can't suppress the
# entire ``google.com`` host, so we fall back to a path-anchored substring
# check.  Keep this list short for the same reason as above.
_SUPPRESS_TERMINAL_URL_SUBSTRINGS: tuple[str, ...] = (
    "google.com/recaptcha",
)


def _is_suppressed_terminal(url: str) -> bool:
    """Return True when *url* points at a cloaking/challenge gate we never
    want to chase as a child kit.

    Host match is suffix-based (so ``sub.challenges.cloudflare.com`` is
    covered).  URL substring fallback covers path-anchored gates like
    reCAPTCHA where we can't blanket-suppress the whole host.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        host = ""
    if host:
        for suffix in _SUPPRESS_TERMINAL_HOSTS:
            if host == suffix or host.endswith("." + suffix):
                return True
    return any(sub in url for sub in _SUPPRESS_TERMINAL_URL_SUBSTRINGS)

# Content-type prefixes worth saving the body of. JS and JSON responses are
# useful for downstream deobfuscation; landing HTML is already captured by
# the downstream browser_download_kit when the URL promotes to a child kit.
_CAPTURABLE_CONTENT_TYPES: tuple[str, ...] = (
    "text/html",
    "application/xhtml",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "text/plain",
    "text/xml",
    "application/xml",
)

# Request resource_types worth classifying as "the SVG fetched something."
_INTERESTING_RESOURCE_TYPES: frozenset[str] = frozenset({
    "document", "script", "xhr", "fetch", "other",
})

# Resource types that are usually static assets. Recorded but never promoted
# to terminal URLs.
_STATIC_RESOURCE_TYPES: frozenset[str] = frozenset({
    "image", "stylesheet", "font", "media", "manifest",
})

_VIEWPORT = {"width": 1280, "height": 1024}
_DEFAULT_TIMEOUT_SEC = 30
_DEFAULT_SETTLE_SEC = 4.0
_MAX_BODY_BYTES = 512 * 1024  # 512 KB per captured resource
_MAX_CAPTURED_RESOURCES = 50

# Filename sanitiser shared with browser_downloader semantics.
_SAFE_NAME_RE = re.compile(r"[^\w.\-]")


@dataclass
class SVGExecResult:
    """Outcome of detonating one SVG file in the active harness."""

    svg_path: str
    urls_discovered: list[str] = field(default_factory=list)
    terminal_urls: list[str] = field(default_factory=list)
    navigations: list[str] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    resources_saved: int = 0
    network_events: int = 0
    page_html: str | None = None
    status: str = "ok"  # "ok" | "camoufox_missing" | "timeout" | "error"
    error: str | None = None
    duration_seconds: float = 0.0


def _sanitize_filename(url: str, index: int) -> str:
    """Produce a stable per-resource filename under ``_browser_resources/``."""
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        if path and path != "/":
            name = path.rsplit("/", 1)[-1].split("?", 1)[0]
            name = _SAFE_NAME_RE.sub("_", name)[:80]
            if name and name != "_":
                return f"{index:03d}_{name}"
        domain = (parsed.hostname or "unknown")[:40]
        return f"{index:03d}_{_SAFE_NAME_RE.sub('_', domain)}"
    except Exception:
        return f"{index:03d}_resource"


def _build_wrapper_html(svg_text: str, *, dawa_value: str | None) -> str:
    """Return an HTML document that embeds the SVG for Camoufox to navigate.

    ``dawa_value`` is the recipient-email-derived value that real loader
    scripts read via ``window.dawa`` to construct the per-victim URL.  We
    set it via ``<script>`` **before** the SVG so inline SVG scripts see it.
    """
    dawa_init = ""
    if dawa_value is not None:
        # JSON-encode for safe embedding inside a <script> block.
        dawa_init = f"<script>window.dawa={json.dumps(dawa_value)};</script>"

    return (
        "<!DOCTYPE html>"
        "<html><head><meta charset='utf-8'>"
        "<style>body{margin:0;display:flex;justify-content:center;"
        "align-items:center;min-height:100vh;background:#fff;}"
        "svg{max-width:100%;max-height:100vh;}</style>"
        f"{dawa_init}"
        "</head><body>"
        f"{svg_text}"
        "</body></html>"
    )


def _looks_like_landing(
    url: str,
    content_type: str,
    status: int,
    resource_type: str,
) -> bool:
    """Heuristic: does a captured response look like a credential landing page?

    Requires a 2xx/3xx status, an HTML-ish content type, and a request
    classified as ``document`` or ``fetch``/``xhr`` (rules out `<img>` /
    ``<link rel=icon>`` noise).  First-party cloaking-gate hosts (Turnstile,
    hCaptcha, reCAPTCHA) are also rejected here so they never become child
    kits — they're ephemeral interstitials, not the phishing payload.
    """
    if _is_suppressed_terminal(url):
        return False
    if status and not (200 <= status < 400):
        return False
    ct = content_type.lower()
    if not any(ct.startswith(p) for p in _LANDING_CONTENT_TYPES):
        return False
    return resource_type in {"document", "fetch", "xhr", "other"}


def _should_capture_body(content_type: str) -> bool:
    ct = content_type.lower()
    return any(ct.startswith(p) for p in _CAPTURABLE_CONTENT_TYPES)


def derive_dawa_from_email(email: str | None) -> str | None:
    """Return the base64-encoded email recipients expect at ``window.dawa``.

    The sanitized loader template sets ``window.dawa='<b64_email>'`` at the
    top of the SVG. When we override it via init_script we need to match
    the same encoding so the decoder's URL builder doesn't produce garbage.
    """
    if not email:
        return None
    try:
        return base64.b64encode(email.strip().encode("utf-8")).decode("ascii")
    except Exception:
        return None


async def _execute_svg_async(
    svg_path: Path,
    out_dir: Path,
    *,
    dawa_value: str | None,
    timeout: int,
    max_requests: int,
) -> SVGExecResult:
    """Async core of the harness — see ``execute_svg_with_capture`` for docs."""
    result = SVGExecResult(svg_path=str(svg_path))
    start = time.monotonic()

    try:
        from camoufox.async_api import AsyncCamoufox

        from darla.utils.egress import camoufox_egress_kwargs
    except ImportError:
        result.status = "camoufox_missing"
        result.error = "camoufox not installed (pip install darla[browser])"
        return result

    try:
        svg_bytes = svg_path.read_bytes()
    except Exception as e:
        result.status = "error"
        result.error = f"svg_read_error:{e}"
        return result

    svg_text = svg_bytes.decode("utf-8", errors="replace")
    wrapper = _build_wrapper_html(svg_text, dawa_value=dawa_value)

    out_dir.mkdir(parents=True, exist_ok=True)
    resources_dir = out_dir / "_browser_resources"
    screenshots_dir = out_dir / "_screenshots"

    # Write the wrapper to a temp file. ``file://`` URLs let Camoufox navigate
    # to an offline document, and the init_script still runs before inline
    # SVG scripts — which matters for the ``window.dawa`` override.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", encoding="utf-8", delete=False,
    ) as tmp:
        tmp.write(wrapper)
        tmp_path = Path(tmp.name)

    # Network capture state
    network_log: list[dict] = []
    captured_responses: list[dict] = []
    navigations: list[str] = []
    request_count = 0
    response_counter = 0

    async def _on_request(request):
        nonlocal request_count
        request_count += 1
        # Hard cap — abusive pages could spam us with thousands of requests.
        if request_count > max_requests:
            return
        network_log.append({
            "type": "request",
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "timestamp": round(time.monotonic() - start, 3),
        })

    async def _on_response(response):
        nonlocal response_counter
        ct = response.headers.get("content-type", "")
        entry = {
            "type": "response",
            "url": response.url,
            "status": response.status,
            "content_type": ct,
            "resource_type": getattr(response.request, "resource_type", ""),
            "timestamp": round(time.monotonic() - start, 3),
        }
        network_log.append(entry)

        # Capture body for text-ish resources, up to a per-resource cap.
        if (
            response_counter < _MAX_CAPTURED_RESOURCES
            and _should_capture_body(ct)
            and not response.url.startswith("file://")
        ):
            try:
                body = await response.body()
                if body and len(body) < _MAX_BODY_BYTES:
                    response_counter += 1
                    captured_responses.append({
                        "url": response.url,
                        "status": response.status,
                        "content_type": ct,
                        "resource_type": entry["resource_type"],
                        "body": body,
                        "index": response_counter,
                    })
            except Exception:
                pass  # Response may be closed/redirected

    async def _on_frame_nav(frame):
        try:
            url = frame.url
        except Exception:
            return
        if url and url not in ("about:blank", tmp_path.resolve().as_uri()):
            navigations.append(url)

    try:
        async with AsyncCamoufox(
            **camoufox_egress_kwargs(),
            headless="virtual",
            humanize=False,
            block_webrtc=True,
            disable_coop=True,
            i_know_what_im_doing=True,
        ) as browser:
            context = await browser.new_context(
                viewport=_VIEWPORT,
                ignore_https_errors=True,
            )
            page = await context.new_page()
            page.set_default_timeout(timeout * 1000)
            page.set_default_navigation_timeout(timeout * 1000)

            # Pre-inject runtime state the SVG's decoder expects.  This runs
            # before any page script, including inline <script> inside the
            # SVG, so the override lands in time.
            if dawa_value is not None:
                init_js = f"window.dawa = {json.dumps(dawa_value)};"
                await page.add_init_script(init_js)

            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("framenavigated", _on_frame_nav)

            # Popups — record the target URL but don't actually follow.
            async def _on_popup(popup):
                with contextlib.suppress(Exception):
                    navigations.append(popup.url)
            page.on("popup", _on_popup)

            try:
                await page.goto(
                    tmp_path.resolve().as_uri(), wait_until="domcontentloaded",
                )
            except Exception as e:
                logger.debug("SVG wrapper nav exception: %s", e)

            # Let inline SVG scripts run, atob layers peel, and outbound
            # fetches fire. ``networkidle`` would block indefinitely if the
            # loader keeps polling, so we settle on a wall-clock timeout.
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=min(timeout, 15),
                )
            await asyncio.sleep(_DEFAULT_SETTLE_SEC)

            # Snapshot the final DOM — useful when the loader rewrote
            # innerHTML or injected a ``<script src>``.
            try:
                page_html = await page.content()
            except Exception:
                page_html = None

            # Screenshot (best-effort).
            try:
                screenshots_dir.mkdir(parents=True, exist_ok=True)
                shot_path = screenshots_dir / "04_svg_active.png"
                await page.screenshot(path=str(shot_path), full_page=True)
                result.screenshots.append(str(shot_path))
            except Exception as e:
                logger.debug("SVG active screenshot failed: %s", e)

            await context.close()

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        logger.exception("SVG active execution failed for %s", svg_path)
    finally:
        with contextlib.suppress(Exception):
            tmp_path.unlink(missing_ok=True)

    # -----------------------------------------------------------------
    # Post-process captured network into the result
    # -----------------------------------------------------------------
    result.network_events = len(network_log)

    # Save page.html
    if page_html:
        try:
            page_path = out_dir / "svg_active_page.html"
            page_path.write_text(page_html, encoding="utf-8")
            result.page_html = str(page_path)
        except Exception:
            pass

    # Save captured resources
    manifest_entries: list[dict] = []
    if captured_responses:
        try:
            resources_dir.mkdir(parents=True, exist_ok=True)
            for resp in captured_responses:
                try:
                    fname = _sanitize_filename(resp["url"], resp["index"])
                    ct = resp["content_type"].lower()
                    if "javascript" in ct and not fname.endswith(".js"):
                        fname += ".js"
                    elif "json" in ct and not fname.endswith(".json"):
                        fname += ".json"
                    elif "html" in ct and not any(
                        fname.endswith(e) for e in (".html", ".htm", ".php")
                    ):
                        fname += ".html"
                    res_path = resources_dir / fname
                    body = resp["body"]
                    if isinstance(body, bytes):
                        try:
                            res_path.write_text(
                                body.decode("utf-8", errors="replace"),
                                encoding="utf-8",
                            )
                        except Exception:
                            res_path.write_bytes(body)
                    else:
                        res_path.write_text(str(body), encoding="utf-8")
                    result.resources_saved += 1
                    manifest_entries.append({
                        "filename": f"_browser_resources/{fname}",
                        "url": resp["url"],
                        "status": resp.get("status"),
                        "content_type": resp.get("content_type", ""),
                        "resource_type": resp.get("resource_type", ""),
                        "index": resp["index"],
                    })
                except Exception as e:
                    logger.debug(
                        "Failed to save SVG-active resource %s: %s",
                        resp.get("url"), e,
                    )
            # Manifest appended rather than overwritten — browser_downloader
            # may have produced its own for httpx-download kits.
            manifest_path = resources_dir / "_svg_active_manifest.json"
            manifest_path.write_text(
                json.dumps(manifest_entries, indent=2), encoding="utf-8",
            )
        except Exception as e:
            logger.debug("Failed to persist SVG-active resources: %s", e)

    # Derive URL lists from the network log (deduplicated, order-preserved).
    seen_urls: set[str] = set()
    seen_terminal: set[str] = set()

    # Map request url -> resource_type so terminal classification can use it
    # even when only the response event is present.
    req_resource_types: dict[str, str] = {}
    for ev in network_log:
        if ev["type"] == "request":
            req_resource_types.setdefault(
                ev["url"], ev.get("resource_type", ""),
            )

    for ev in network_log:
        url = ev["url"]
        if not url or url.startswith("file://") or url.startswith("data:"):
            continue
        if not url.startswith(("http://", "https://")):
            continue

        if url not in seen_urls:
            seen_urls.add(url)
            result.urls_discovered.append(url)

        if ev["type"] == "response":
            rtype = ev.get("resource_type") or req_resource_types.get(url, "")
            if (
                url not in seen_terminal
                and _looks_like_landing(
                    url,
                    ev.get("content_type", ""),
                    ev.get("status", 0),
                    rtype,
                )
            ):
                seen_terminal.add(url)
                result.terminal_urls.append(url)

    # Navigations (framenavigated + popups) are candidate terminals — but
    # cloaking-gate navigations (Turnstile, hCaptcha) are recorded only as
    # discovered/navigations, never promoted to terminals.  Otherwise the
    # chain crawler spawns a child kit that re-renders the same interstitial
    # across every polymorphism generation.
    for nav in navigations:
        if not nav or not nav.startswith(("http://", "https://")):
            continue
        if nav not in seen_urls:
            seen_urls.add(nav)
            result.urls_discovered.append(nav)
        if nav not in result.navigations:
            result.navigations.append(nav)
        if _is_suppressed_terminal(nav):
            continue
        if nav not in seen_terminal:
            seen_terminal.add(nav)
            result.terminal_urls.append(nav)

    # Persist the full network log alongside the resources for later audit.
    try:
        requests_path = out_dir / "svg_active_requests.json"
        requests_path.write_text(
            json.dumps(network_log, indent=2, default=str), encoding="utf-8",
        )
    except Exception:
        pass

    result.duration_seconds = round(time.monotonic() - start, 3)
    return result


def execute_svg_with_capture(
    svg_path: Path | str,
    out_dir: Path | str,
    *,
    dawa_value: str | None = None,
    timeout: int = _DEFAULT_TIMEOUT_SEC,
    max_requests: int = 200,
) -> SVGExecResult:
    """Synchronous entry point — detonate *svg_path* and return captured URLs.

    Parameters
    ----------
    svg_path
        Path to the SVG attachment on disk.
    out_dir
        Directory under which ``_browser_resources/``, ``_screenshots/``,
        ``svg_active_page.html`` and ``svg_active_requests.json`` are written.
    dawa_value
        Value to pre-set at ``window.dawa`` before the SVG executes. Pass
        :func:`derive_dawa_from_email` of the recipient address if known.
    timeout
        Total wall-clock budget for navigation + JS settle, in seconds.
    max_requests
        Hard cap on captured outbound requests — guards against runaway
        polling loops.
    """
    return asyncio.run(
        _execute_svg_async(
            Path(svg_path), Path(out_dir),
            dawa_value=dawa_value,
            timeout=timeout,
            max_requests=max_requests,
        )
    )
