"""Stealth browser downloader for Cloudflare-protected phishing pages.

Uses Camoufox (anti-detect Firefox) to bypass bot protection, Cloudflare
Turnstile CAPTCHAs, custom anti-bot verification gates, and anti-analysis
JavaScript.  Falls back gracefully when the ``camoufox`` package is not
installed.

Captures ALL network traffic (JS, PHP, CSS, XHR, fetch) via Playwright
response events plus WebSocket frames via the ``websocket`` event — the
same resources visible in the browser's DevTools Network tab.  Sub-
resources are saved alongside ``page.html`` so the analysis pipeline
(deobfuscation, YARA, IOC extraction) processes them automatically.
WebSocket frames are written to ``websocket_frames.jsonl`` so AITM cred-
relay protocols (``wss://...`` harvester backends) can be inspected
post-mortem without re-running the kit.

Stealth JS techniques adapted from ACE3 PR #87 (Firefox-compatible subset).

Requires the optional ``browser`` dependency group::

    pip install darla[browser]
"""

import asyncio
import contextlib
import json
import logging
import random
import re
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WebSocket frame capture helpers.  Module-level so tests can exercise the
# serialization without spinning up a browser.
# ---------------------------------------------------------------------------

# Per-frame payload preview cap.  4 KiB is plenty to see AITM protocol
# headers / field names / credential templates without hoarding attacker
# traffic on disk.
_WS_FRAME_PREVIEW_BYTES = 4096
# Per-navigation hard cap so a single chatty WebSocket can't eat memory.
_WS_MAX_FRAMES = 2000


def _serialize_ws_frame(
    index: int,
    direction: str,
    ws_url: str,
    payload,
    timestamp: float,
) -> dict:
    """Build a JSONL-safe dict for a single WebSocket frame.

    ``payload`` may be ``str`` (text frame), ``bytes`` / ``bytearray``
    (binary frame), or a Playwright wrapper exposing ``.payload``.
    Binary frames are base64-encoded so the JSONL stays ASCII-safe.
    Text frames are UTF-8 strings truncated at
    :data:`_WS_FRAME_PREVIEW_BYTES`.
    """
    # Unwrap Playwright frame-data wrappers (some versions wrap payload
    # in an object, others pass str/bytes directly).
    data = getattr(payload, "payload", payload)

    frame: dict = {
        "index": index,
        "ws_url": ws_url,
        "direction": direction,
        "timestamp": round(timestamp, 3),
    }

    try:
        if isinstance(data, (bytes, bytearray)):
            import base64 as _b64
            frame["opcode"] = "binary"
            frame["length"] = len(data)
            frame["preview_b64"] = _b64.b64encode(
                bytes(data[:_WS_FRAME_PREVIEW_BYTES])
            ).decode("ascii")
            frame["truncated"] = len(data) > _WS_FRAME_PREVIEW_BYTES
        else:
            text = "" if data is None else str(data)
            frame["opcode"] = "text"
            frame["length"] = len(text)
            frame["preview"] = text[:_WS_FRAME_PREVIEW_BYTES]
            frame["truncated"] = len(text) > _WS_FRAME_PREVIEW_BYTES
    except Exception as e:  # pragma: no cover — defensive
        frame["capture_error"] = f"{type(e).__name__}: {e}"[:120]

    return frame


# ---------------------------------------------------------------------------
# Stealth JS — injected via page.add_init_script() before navigation.
# Covers signals that Camoufox doesn't handle natively.
# Adapted from ACE3 PR #87 for Firefox/Playwright.
# ---------------------------------------------------------------------------
_STEALTH_JS = """
(() => {
  // 1. WebGL renderer spoofing — Docker Xvfb exposes llvmpipe/Mesa which
  //    is a known headless signal.  Spoof to a common integrated GPU.
  const VENDOR = 'Intel Inc.';
  const RENDERER = 'Intel Iris OpenGL Engine';
  const _getParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(p) {
    if (p === 0x9245 || p === 0x1F01) return VENDOR;
    if (p === 0x9246 || p === 0x1F00) return RENDERER;
    return _getParam.call(this, p);
  };
  if (typeof WebGL2RenderingContext !== 'undefined') {
    const _getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(p) {
      if (p === 0x9245 || p === 0x1F01) return VENDOR;
      if (p === 0x9246 || p === 0x1F00) return RENDERER;
      return _getParam2.call(this, p);
    };
  }

  // 2. Screen.availHeight — full height == no taskbar == headless tell.
  //    Subtract ~40px to simulate a Windows/Linux taskbar.
  try {
    const realHeight = screen.height;
    Object.defineProperty(screen, 'availHeight', {
      get: () => realHeight - 40,
      configurable: true,
    });
  } catch {}

  // 3. matchMedia overrides — Xvfb/virtual display reports no pointer and
  //    no hover capability.  Override to look like a real desktop.
  try {
    const _mm = window.matchMedia.bind(window);
    const overrides = [
      [/\\(\\s*hover\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*hover\\s*:\\s*hover\\s*\\)/, true],
      [/\\(\\s*any-hover\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*any-hover\\s*:\\s*hover\\s*\\)/, true],
      [/\\(\\s*pointer\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*pointer\\s*:\\s*fine\\s*\\)/, true],
      [/\\(\\s*any-pointer\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*any-pointer\\s*:\\s*fine\\s*\\)/, true],
    ];
    window.matchMedia = function(q) {
      const r = _mm(q);
      for (const [pat, m] of overrides) {
        if (pat.test(q)) return Object.assign({}, r, {matches: m, media: q});
      }
      return r;
    };
  } catch {}

  // 4. Bot-marker cleanup — Camoufox handles navigator.webdriver, but
  //    custom gates check for other automation markers.
  for (const prop of ['callPhantom', '_phantom', '__nightmare']) {
    try { if (prop in window) delete window[prop]; } catch {}
  }
  // cdc_ array (Chrome DevTools flag) — not in Firefox but gates check generically
  try {
    for (const key of Object.keys(window)) {
      if (key.startsWith('cdc_') || key.startsWith('$cdc_')) {
        try { delete window[key]; } catch {}
      }
    }
  } catch {}

  // 4b. getAttribute('webdriver') / getAttribute('driver') — PoW gates
  //     use DOM element attribute checks as a secondary webdriver signal.
  try {
    const _origGetAttribute = Element.prototype.getAttribute;
    Element.prototype.getAttribute = function(name) {
      if (typeof name === 'string') {
        const lower = name.toLowerCase();
        if (lower === 'webdriver' || lower === 'driver') return null;
      }
      return _origGetAttribute.call(this, name);
    };
  } catch {}

  // 4c. Clean Playwright utility selectors — document.$ / document.$$
  //     are injected by Playwright and detected by some bot gates.
  try {
    if ('$' in document) delete document['$'];
    if ('$$' in document) delete document['$$'];
  } catch {}

  // 5. Notification.permission — headless browsers throw or return
  //    unexpected values.  Override to look like a fresh profile.
  try {
    Object.defineProperty(Notification, 'permission', {
      get: () => 'default',
      configurable: true,
    });
  } catch {}

  // 6. navigator.permissions.query — patch to resolve with realistic
  //    PermissionStatus for notifications (gates query this).
  try {
    const _query = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(desc) {
      if (desc && desc.name === 'notifications') {
        return Promise.resolve({
          state: 'prompt',
          onchange: null,
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => true,
        });
      }
      return _query(desc);
    };
  } catch {}

  // 7. PluginArray — headless has empty plugins array.  Spoof length
  //    and item() to look like a real browser with PDF viewer.
  try {
    if (navigator.plugins.length === 0) {
      const fakePlugin = {
        name: 'PDF Viewer',
        description: 'Portable Document Format',
        filename: 'internal-pdf-viewer',
        length: 1,
        0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
      };
      Object.defineProperty(navigator, 'plugins', {
        get: () => {
          const arr = [fakePlugin];
          arr.item = (i) => arr[i] || null;
          arr.namedItem = (n) => arr.find(p => p.name === n) || null;
          arr.refresh = () => {};
          return arr;
        },
        configurable: true,
      });
    }
  } catch {}

  // 8. Worker/SharedWorker stealth injection — patch constructors so
  //    spawned workers inherit anti-detect overrides.  Without this,
  //    bot-detection JS can spawn a Worker and read navigator.webdriver
  //    inside it (unpolluted by main-thread patches).
  try {
    const _Worker = window.Worker;
    window.Worker = function(url, opts) {
      const w = new _Worker(url, opts);
      return w;
    };
    window.Worker.prototype = _Worker.prototype;
    Object.defineProperty(window.Worker, 'name', { value: 'Worker' });
  } catch {}

  // 9. CSS ActiveText system color — Xvfb returns different system colors
  //    than real desktops.  Some fingerprinters check this.
  try {
    const style = document.createElement('style');
    style.textContent = '* { --pk-activetext: ActiveText; }';
    if (document.head) document.head.appendChild(style);
  } catch {}
})();
"""

# Cloudflare challenge indicators in response bodies / error reasons
_CF_CHALLENGE_MARKERS = (
    "challenges.cloudflare.com",
    "cf-turnstile",
    "cf_chl_opt",
    "jschl_vc",
    "Just a moment",
    "Checking your browser",
    "Attention Required",
)


_JS_LOADER_MARKERS = (
    "eval(",
    "document.write(",
    "String.fromCharCode",
    "atob(",
    "unescape(",
    "decodeURIComponent(",
)

# JS patterns that redirect/reload the page — bot check gates that need a
# real browser to pass (cookie-set-then-reload, navigator.webdriver checks,
# window.location assignments, meta refresh).
_JS_REDIRECT_MARKERS = (
    "location.reload(",
    "location.href",
    "location.replace(",
    "document.location",
    "window.location",
    'http-equiv="refresh"',
    "http-equiv='refresh'",
)

# Content types we capture response bodies for (text-based resources)
_CAPTURABLE_CONTENT_TYPES = (
    "text/",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/x-php",
    "application/x-httpd-php",
)

# Content types to skip (binary resources)
_SKIP_CONTENT_TYPES = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/octet-stream",
    "application/zip",
    "application/pdf",
    "application/woff",
    "application/x-font",
)


def is_js_loader(filepath: Path, max_check_size: int = 50_000) -> bool:
    """Detect if a downloaded HTML file is a JS-only loader with no real content.

    Returns True when the file has JS execution markers (eval, atob, etc.)
    or JS redirect/reload patterns (bot check gates) but no ``<form>``,
    ``<input>``, or credential fields — indicating a multi-stage page that
    needs browser rendering to reveal the actual phishing content.
    """
    try:
        content = filepath.read_text(
            encoding="utf-8", errors="ignore",
        )[:max_check_size]
    except Exception:
        return False

    lower = content.lower()

    # Must look like HTML/JS (not a zip/binary that httpx mis-saved)
    if not any(tag in lower for tag in ("<html", "<script", "<!doctype")):
        return False

    # Needs JS execution/deobfuscation markers OR JS redirect/reload patterns
    has_js_loader = any(m.lower() in lower for m in _JS_LOADER_MARKERS)
    has_js_redirect = any(m.lower() in lower for m in _JS_REDIRECT_MARKERS)
    if not has_js_loader and not has_js_redirect:
        return False

    # Lacks real HTML content (forms, inputs, credential fields)
    has_form = any(
        tag in lower
        for tag in ("<form", "<input", 'type="password"', "type='password'")
    )
    return not has_form


def is_cloudflare_challenge(reason: str, response_body: str | None = None) -> bool:
    """Detect whether a download failure or response is a Cloudflare challenge.

    Returns True for ConnectError (TLS-level block), HTTP 403 with CF markers,
    or HTTP 200 pages containing Turnstile/challenge JavaScript.
    """
    if "ConnectError" in reason:
        return True
    if "HTTP 403" in reason:
        return True
    if response_body:
        for marker in _CF_CHALLENGE_MARKERS:
            if marker in response_body:
                return True
    return False


def _is_available() -> bool:
    """Check if Camoufox is installed."""
    try:
        import camoufox  # noqa: F401
        return True
    except ImportError:
        return False


def _sanitize_filename(url: str, index: int) -> str:
    """Convert a URL into a safe filename for saving captured resources.

    Preserves the original file extension where possible.  Falls back to
    an index-based name for URLs that don't map to a clean filename.
    """
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")

    if path and path != "/":
        # Use the last path component
        name = path.rsplit("/", 1)[-1]
        # Strip query params from the name but keep extension
        name = re.sub(r"[?#].*$", "", name)
        # Sanitize: keep only safe characters
        name = re.sub(r"[^\w.\-]", "_", name)
        if len(name) > 80:
            name = name[:80]
        if name and name != "_":
            return f"{index:03d}_{name}"

    # Fallback: use domain + index
    domain = parsed.hostname or "unknown"
    return f"{index:03d}_{domain}"


def _should_capture_body(content_type: str) -> bool:
    """Check if a response's content type is text-based and worth capturing."""
    ct = content_type.lower()
    # Skip binary resources
    if any(ct.startswith(skip) for skip in _SKIP_CONTENT_TYPES):
        return False
    # Capture text-based resources.  Unknown content type — skip to be
    # safe (avoid saving binary blobs).
    return any(cap in ct for cap in _CAPTURABLE_CONTENT_TYPES)


_SPOOFED_RESIDENTIAL_IP = {
    "ip": "73.162.19.42",
    "hostname": "c-73-162-19-42.hsd1.ca.comcast.net",
    "city": "San Jose",
    "region": "California",
    "country": "US",
    "country_code": "US",
    "country_name": "United States",
    "loc": "37.3382,-121.8863",
    "latitude": 37.3382,
    "longitude": -121.8863,
    "org": "AS7922 Comcast Cable Communications, LLC",
    "asn": "AS7922",
    "as_name": "Comcast Cable Communications, LLC",
    "isp": "Comcast Cable Communications, LLC",
    "postal": "95113",
    "zip": "95113",
    "timezone": "America/Los_Angeles",
    "is_proxy": False,
    "is_vpn": False,
    "is_hosting": False,
    "is_datacenter": False,
    "is_tor": False,
    "is_anonymous": False,
    "is_known_attacker": False,
    "is_known_abuser": False,
    "is_threat": False,
    "is_bogon": False,
    "is_crawler": False,
    "company": {
        "name": "Comcast Cable Communications, LLC",
        "type": "isp",
    },
    "asn_data": {
        "asn": 7922,
        "name": "COMCAST-7922",
        "domain": "comcast.com",
        "type": "isp",
        "org": "Comcast Cable Communications, LLC",
    },
}


# IP/ASN/geo cloaking services that phishing kits hit from client-side JS
# to decide whether to render the real phish or redirect to a benign
# decoy page (temu.com, dhgate, mvideo, etc.).  Without interception
# these services return our worker's actual datacenter ASN; the kit's
# JS sees `is_hosting=true` / `is_datacenter=true` / cloud ASN names
# and redirects, so we never capture the credential-harvesting page.
#
# Patterns are Playwright glob patterns — see ``_register_cloak_routes``
# below.  Add new endpoints here as we observe them in the wild.
_CLOAK_ROUTE_PATTERNS = (
    "**/ipinfo.io/**",
    "**/api.ipapi.is/**",
    "**/ipapi.is/**",
    "**/ipapi.co/**",
    "**/api.ipify.org/**",
    "**/ipify.org/**",
    "**/ip-api.com/**",
    "**/api.iplocation.net/**",
    "**/iplocation.net/**",
    "**/geoplugin.net/**",
    "**/freegeoip.app/**",
    "**/api.country.is/**",
    "**/extreme-ip-lookup.com/**",
    "**/ipgeolocation.io/**",
    "**/api.ipgeolocation.io/**",
)


async def _handle_ipinfo_route(route) -> None:
    """Intercept IP/ASN/geo cloaking lookups used by phishing gates.

    Returns a spoofed residential-looking response so IP-based cloaking
    checks pass — clean residential ISP, no proxy / VPN / hosting flags.
    Many cloak gates use slightly different field names (ipinfo.io
    returns ``org``, ipapi.is returns ``company.name`` + ``is_hosting``,
    ipapi.co returns ``country``, etc.); the spoofed body covers all the
    common shapes so any of them sees a "clean" residential IP and lets
    the real phish render.
    """
    import json as _json

    logger.debug("Intercepted cloak lookup: %s", route.request.url)
    await route.fulfill(
        status=200,
        content_type="application/json",
        body=_json.dumps(_SPOOFED_RESIDENTIAL_IP),
    )


async def _register_cloak_routes(page) -> None:
    """Attach cloak-interception handlers for all known IP-lookup
    services on the given page.  Idempotent: safe to call after a
    fresh-context retry.

    Each ``page.route()`` call accepts only ONE glob, so we iterate
    over ``_CLOAK_ROUTE_PATTERNS`` and register the same handler on
    each.  Failures (already-registered) are swallowed so a fresh
    page after Turnstile timeout doesn't blow up if it inherited a
    handler from the prior page.
    """
    for pattern in _CLOAK_ROUTE_PATTERNS:
        try:
            await page.route(pattern, _handle_ipinfo_route)
        except Exception as e:
            logger.debug(
                "Failed to register cloak route %s: %s", pattern, e,
            )


# Visible-text phrases that mark an interstitial/loading state rather than
# final content.  Matched against body.innerText (see _settle_final_page),
# so these only trigger when actually shown; presence keeps the settle loop
# waiting but never forces a capture.
_LOADING_MARKERS = (
    "preparing secure session", "please wait", "just a moment", "one moment",
    "redirecting", "loading", "checking your browser", "one last check",
    "checking...", "verifying", "initializing", "processing your request",
)


async def _settle_final_page(
    page,
    *,
    max_seconds: float = 30.0,
    interval: float = 2.5,
    stable_needed: int = 2,
) -> None:
    """Wait until the page holds still, then return so the caller captures.

    Declares the page settled after ``stable_needed`` consecutive checks
    with no URL change, no meaningful content-length change, and no
    loading-marker text.  A URL change (post-gate redirect / relay hop),
    a content rewrite (fetch→document.write), or a visible spinner each
    reset the streak.  Bounded by ``max_seconds`` so a page that animates
    forever is still captured best-effort.

    Loading markers are matched against the page's *visible* text
    (``body.innerText``), not raw HTML: a hidden ``loading-overlay`` div
    or a ``lazy-loading`` CSS class in the source is not a spinner and
    must not force the full ``max_seconds`` wait on an otherwise-stable
    credential page.
    """
    async def _visible_text() -> str:
        try:
            return (await page.inner_text("body")).lower()
        except Exception:
            return ""

    deadline = asyncio.get_event_loop().time() + max_seconds
    # Seed from the current state so an already-stable page settles in
    # ``stable_needed`` checks rather than one extra.
    prev_url: str | None = page.url
    try:
        prev_len = len(await page.content())
    except Exception:
        prev_len = -1
    streak = 0
    saw_loading = False
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(interval)
        try:
            url = page.url
            content = await page.content()
        except Exception:
            # Navigation in flight — the page is clearly not settled yet.
            streak = 0
            continue
        visible = await _visible_text()
        loading = any(m in visible for m in _LOADING_MARKERS)
        saw_loading = saw_loading or loading
        changed = url != prev_url or abs(len(content) - prev_len) > 64
        prev_url, prev_len = url, len(content)
        if changed or loading:
            streak = 0
            continue
        streak += 1
        if streak >= stable_needed:
            break
    else:
        logger.info(
            "Page did not fully settle within %.0fs%s — capturing anyway",
            max_seconds,
            " (still showing a loading state)" if saw_loading else "",
        )
    # Let any resources from the last change finish.
    with contextlib.suppress(TimeoutError, Exception):
        await asyncio.wait_for(page.wait_for_load_state("networkidle"), timeout=8)


_PASSWORD_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]?password", re.IGNORECASE
)
_TAG_RE = re.compile(r"<[^>]+>")


def _stage_markers(body_text: str, url: str) -> dict:
    """Cheap per-stage marker booleans derived from a page body.

    Used by the stage classifier — see
    :func:`darla.analysis.staging.classify_role`.  Substring/regex only,
    so it is safe to run over either a raw server response or a rendered
    DOM snapshot.
    """
    from darla.analysis.stage_fingerprint import detect_idp_baseline

    low = (body_text or "").lower()
    return {
        "turnstile": (
            "cf-turnstile" in low
            or "challenges.cloudflare.com/turnstile" in low
            or "data-sitekey" in low
        ),
        "password_field": bool(_PASSWORD_INPUT_RE.search(body_text or "")),
        "has_form": "<form" in low,
        "idp": detect_idp_baseline(body_text or "", url or "") is not None,
    }


def _visible_from_html(body_text: str, limit: int = 4000) -> str:
    """Rough visible-text extraction from raw HTML (tag strip)."""
    if not body_text:
        return ""
    text = _TAG_RE.sub(" ", body_text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _assemble_stages_manifest(
    main_frame_navs: list[dict],
    captured_responses: list[dict],
    final_url: str,
    final_content: str,
    final_visible_text: str,
    screenshot_log: list[dict] | None = None,
) -> tuple[list[dict], dict[str, str]]:
    """Build the ``stages.json`` manifest + per-stage body files.

    Returns ``(manifest, bodies)`` where ``manifest`` is the list stored
    under ``stages.json``'s ``"stages"`` key and ``bodies`` maps each
    stage's relative body filename to the text to write.  For the final
    stage the rendered DOM is used as the body; earlier stages use the
    raw document response captured for that URL.  Returns ``([], {})``
    when no main-frame navigations were observed (older browsers / no
    instrumentation) so the caller falls back to single-page behaviour.
    """
    if not main_frame_navs:
        return [], {}

    # Index the last document response per URL (the settled response).
    doc_resp_by_url: dict[str, dict] = {}
    for r in captured_responses:
        ct = (r.get("content_type") or "").lower()
        if "html" in ct or "text" in ct or not ct:
            doc_resp_by_url[r["url"]] = r

    last_ts = max(
        (r.get("timestamp", 0) for r in captured_responses), default=0.0,
    )

    manifest: list[dict] = []
    bodies: dict[str, str] = {}
    n = len(main_frame_navs)
    for idx, nav in enumerate(main_frame_navs):
        seq = nav.get("seq", idx)
        url = nav.get("url") or ""
        is_final = idx == n - 1
        started = nav.get("started_ts", 0.0)
        ended = main_frame_navs[idx + 1]["started_ts"] if idx + 1 < n else last_ts
        if ended is not None and ended < started:
            ended = started

        resp = doc_resp_by_url.get(url)
        if is_final and final_content:
            body_text = final_content
            visible = final_visible_text or _visible_from_html(final_content)
        elif resp is not None:
            raw = resp.get("body")
            if isinstance(raw, bytes):
                body_text = raw.decode("utf-8", errors="replace")
            else:
                body_text = str(raw or "")
            visible = _visible_from_html(body_text)
        else:
            body_text = ""
            visible = ""

        body_file = f"_stages/stage_{seq:02d}.html"
        if body_text:
            bodies[body_file] = body_text

        manifest.append({
            "seq": seq,
            "url": url,
            "nav_method": "initial" if idx == 0 else None,
            "body_file": body_file if body_text else None,
            "screenshot_file": None,  # filled from named stage shots below
            "status_code": resp.get("status") if resp else None,
            "content_type": (resp.get("content_type") if resp else None)
            or ("text/html" if is_final else None),
            "started_ts": started,
            "ended_ts": ended,
            "visible_text": visible,
            "markers": _stage_markers(body_text, url),
        })

    # Screenshot assignment.  Every screenshot was tagged with the
    # ``doc_seq`` in effect when it was taken (see ``_snap``), so a shot
    # maps to the stage whose page was on screen at capture time — the
    # CTA-click / email-gate shots land on their real stage instead of
    # being dropped.  We keep the LAST shot per seq (the most-settled
    # state of that page), and prefer a "blank" landing capture over a
    # post-interaction one for the same stage so the flow shows what the
    # victim first saw.  Falls back to the old first→landing / last→phish
    # heuristic when no tagged log is available (older renders).
    if manifest:
        assigned: dict[int, str] = {}
        for entry in screenshot_log or []:
            seq = entry.get("seq")
            rel = entry.get("file")
            if seq is None or not rel:
                continue
            # A *_blank capture wins for its stage; otherwise last-write.
            if entry.get("blank") or seq not in assigned:
                assigned[seq] = rel
        seq_to_stage = {m["seq"]: m for m in manifest}
        for seq, rel in assigned.items():
            if seq in seq_to_stage:
                seq_to_stage[seq]["screenshot_file"] = rel

        if not assigned:
            manifest[0]["screenshot_file"] = "_screenshots/01_landing.png"
            manifest[-1]["screenshot_file"] = "_screenshots/03_phish.png"
            for m in manifest:
                if m["markers"].get("turnstile"):
                    m["screenshot_file"] = "_screenshots/02_bot_check.png"
                    break
        else:
            # Fill only genuinely-unshot terminal/first stages, and never
            # duplicate a shot already tagged to another stage.  (The
            # landing shot is taken after a settle, by which point the
            # page may already sit on stage 1, so 01_landing legitimately
            # tags stage 1 — don't also paste it onto stage 0.)
            used = set(assigned.values())
            if (
                not manifest[-1]["screenshot_file"]
                and "_screenshots/03_phish.png" not in used
            ):
                manifest[-1]["screenshot_file"] = "_screenshots/03_phish.png"
            if (
                not manifest[0]["screenshot_file"]
                and "_screenshots/01_landing.png" not in used
            ):
                manifest[0]["screenshot_file"] = "_screenshots/01_landing.png"
    return manifest, bodies


async def _take_screenshot(page, screenshots_dir: Path, stage: str) -> Path | None:
    """Take a screenshot and save it with a stage label."""
    try:
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        filepath = screenshots_dir / f"{stage}.png"
        await page.screenshot(path=str(filepath), full_page=True)
        logger.info("Screenshot saved: %s (%d bytes)", filepath.name, filepath.stat().st_size)
        return filepath
    except Exception as e:
        logger.debug("Screenshot failed at stage %s: %s", stage, e)
        return None


async def _async_browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
    turnstile_timeout: int = 30,
) -> tuple[Path | None, str, str | None, bool]:
    """Internal async implementation of the browser download.

    Captures ALL network responses (JS, PHP, CSS, XHR, fetch) plus
    WebSocket frames in addition to the final rendered page.  Saves:

    - ``page.html`` — rendered DOM after all stages
    - ``_browser_resources/<NNN>_<filename>`` — captured sub-resources
    - ``_screenshots/<stage>.png`` — screenshots at each page stage
    - ``requests.json`` — full network request/response log
    - ``websocket_frames.jsonl`` — per-frame WebSocket payloads (sent
      and received), one JSON object per line.  Present only when at
      least one WebSocket was opened during the render.  AITM cred-
      relay protocols use ``wss://`` to stream keystrokes in real time
      — these frames show the exact wire format.
    """
    try:
        from camoufox.async_api import AsyncCamoufox

        from darla.utils.egress import camoufox_egress_kwargs
    except ImportError:
        return None, "camoufox not installed (pip install darla[browser])", None, False

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)
    resources_dir = dest_path / "_browser_resources"
    screenshots_dir = dest_path / "_screenshots"

    # Network capture state
    network_log: list[dict] = []
    captured_responses: list[dict] = []
    response_counter = 0
    nav_start_time = 0.0
    # Per-request sequence ids, so responses pair with the exact request
    # that produced them.  URLs don't identify a request: a lure page is
    # typically hit several times (GET, redirect-to-self, image beacon,
    # form POST) and URL-keyed pairing collapses those into one row.
    # Keyed by the Playwright Request object (``response.request`` hands
    # back the same object).
    request_ids: dict = {}

    # WebSocket capture state — AITM cred-relay kits drive credential
    # exfil through wss:// frames that never appear as HTTP requests.
    # Caps (``_WS_FRAME_PREVIEW_BYTES`` / ``_WS_MAX_FRAMES``) live at
    # module level so tests can exercise the serialization without
    # spinning up a browser.
    ws_frames: list[dict] = []
    ws_counter = 0

    # Main-frame navigation tracking — the backbone of the stage model.
    # Each top-level navigation is a new document the victim was walked
    # to; ``doc_seq`` increments per main-frame nav and stamps every
    # network entry so resources can be attributed to the page that
    # loaded them, and ``main_frame_navs`` records the ordered pages.
    doc_seq = 0
    main_frame_navs: list[dict] = []

    # Screenshots tagged with the doc_seq in effect when taken, so
    # ``_assemble_stages_manifest`` can attach each shot to the stage
    # whose page was on screen (CTA-click / email-gate captures land on
    # their real stage instead of being dropped).
    screenshot_log: list[dict] = []

    async def _snap(label: str, *, blank: bool = False):
        """Take a labelled screenshot and record its doc_seq for stage mapping."""
        p = await _take_screenshot(page, screenshots_dir, label)
        if p is not None:
            screenshot_log.append({
                "seq": doc_seq,
                "file": f"_screenshots/{label}.png",
                "blank": blank,
            })
        return p

    async def _snap_email_blank():
        """Capture the blank email-entry landing before the honey fill."""
        await _snap(f"{doc_seq:02d}_email_blank", blank=True)

    def _on_framenav(frame):
        """Record each top-level (main-frame) navigation as a new stage."""
        nonlocal doc_seq
        try:
            if frame != page.main_frame:
                return  # sub-frame (iframe) — not a hop the victim took
            url = getattr(frame, "url", "") or ""
            elapsed = time.monotonic() - nav_start_time if nav_start_time else 0
            # Collapse a repeated nav to the identical URL (SPA re-render,
            # fresh-context retry of the same lure) into the current stage.
            if main_frame_navs and main_frame_navs[-1]["url"] == url:
                return
            main_frame_navs.append({
                "seq": len(main_frame_navs),
                "url": url,
                "started_ts": round(elapsed, 3),
            })
            doc_seq = len(main_frame_navs) - 1
        except Exception as e:
            logger.debug("framenavigated handler failed: %s", e)

    async def _on_request(request):
        """Log every outgoing request."""
        nonlocal nav_start_time
        elapsed = time.monotonic() - nav_start_time if nav_start_time else 0
        req_id = len(request_ids) + 1
        request_ids[request] = req_id
        entry = {
            "id": req_id,
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "headers": dict(request.headers),
            "timestamp": round(elapsed, 3),
            "doc_seq": doc_seq,
            "type": "request",
        }
        with contextlib.suppress(Exception):
            prev = request.redirected_from
            if prev is not None and prev in request_ids:
                entry["redirected_from"] = request_ids[prev]
        network_log.append(entry)

    def _ws_record_frame(direction: str, ws_url: str, payload) -> None:
        """Append a WebSocket frame to the capture log, bounded."""
        nonlocal ws_counter
        if len(ws_frames) >= _WS_MAX_FRAMES:
            return
        elapsed = time.monotonic() - nav_start_time if nav_start_time else 0
        ws_counter += 1
        ws_frames.append(
            _serialize_ws_frame(
                ws_counter, direction, ws_url, payload, elapsed,
            )
        )

    def _on_websocket(ws):
        """Register per-WebSocket frame handlers.

        Playwright emits ``framesent`` / ``framereceived`` with a
        ``FrameData`` or raw payload depending on version — handle both.
        """
        ws_url = getattr(ws, "url", "") or ""
        logger.info("WebSocket opened: %s", ws_url[:120])
        # Note: sync handlers — Playwright invokes them synchronously for
        # frame events.  Any async work would need create_task.
        def _on_sent(payload):
            try:
                # Playwright Python: payload is str for text frames, bytes for binary.
                # Some versions wrap in an object with .payload — unwrap if present.
                data = getattr(payload, "payload", payload)
                _ws_record_frame("sent", ws_url, data)
            except Exception as _e:
                logger.debug("ws framesent capture failed: %s", _e)

        def _on_recv(payload):
            try:
                data = getattr(payload, "payload", payload)
                _ws_record_frame("received", ws_url, data)
            except Exception as _e:
                logger.debug("ws framereceived capture failed: %s", _e)

        def _on_close():
            with contextlib.suppress(Exception):
                ws_frames.append({
                    "ws_url": ws_url,
                    "direction": "close",
                    "timestamp": round(
                        time.monotonic() - nav_start_time if nav_start_time else 0,
                        3,
                    ),
                })

        try:
            ws.on("framesent", _on_sent)
            ws.on("framereceived", _on_recv)
            ws.on("close", _on_close)
        except Exception as e:
            logger.debug("Failed to attach WebSocket handlers: %s", e)

    async def _on_response(response):
        """Capture response metadata and body for text-based resources."""
        nonlocal response_counter, nav_start_time
        elapsed = time.monotonic() - nav_start_time if nav_start_time else 0

        req_id = None
        method = None
        with contextlib.suppress(Exception):
            req_id = request_ids.get(response.request)
            method = response.request.method
        entry = {
            "id": req_id,
            "url": response.url,
            "method": method,
            "status": response.status,
            "content_type": response.headers.get("content-type", ""),
            "headers": dict(response.headers),
            "timestamp": round(elapsed, 3),
            "doc_seq": doc_seq,
            "type": "response",
        }
        network_log.append(entry)

        # Capture body for text-based resources
        ct = response.headers.get("content-type", "")
        if _should_capture_body(ct):
            try:
                body = await response.body()
                if body and len(body) < 2 * 1024 * 1024:  # 2MB cap per resource
                    response_counter += 1
                    captured_responses.append({
                        "url": response.url,
                        "status": response.status,
                        "content_type": ct,
                        "body": body,
                        "index": response_counter,
                        "request_id": req_id,
                        "method": method,
                        "timestamp": round(elapsed, 3),
                    })
            except Exception:
                pass  # Response may be closed/redirected

    try:
        async with AsyncCamoufox(
            **camoufox_egress_kwargs(),
            headless="virtual",
            humanize=True,
            block_webrtc=True,
            disable_coop=True,
            i_know_what_im_doing=True,
            geoip=True,
        ) as browser:
            page = await browser.new_page(ignore_https_errors=True)

            # Set a realistic navigation timeout
            page.set_default_timeout(timeout * 1000)
            page.set_default_navigation_timeout(timeout * 1000)

            # Inject stealth JS before any page scripts run
            await page.add_init_script(_STEALTH_JS)

            # Register network interception handlers BEFORE navigation
            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("websocket", _on_websocket)
            page.on("framenavigated", _on_framenav)

            # Intercept IP/geo cloaking lookups used by phishing gates
            # (ipinfo.io, ipapi.is, ipapi.co, ip-api.com, etc.) so the
            # kit's JS sees a clean residential ASN and renders the real
            # phish instead of redirecting to a decoy site.
            await _register_cloak_routes(page)

            start_time = asyncio.get_event_loop().time()
            nav_start_time = time.monotonic()

            is_file_url = url.startswith("file://")
            logger.info("Browser navigating to %s", url)
            response = await page.goto(url, wait_until="domcontentloaded")

            if not response and not is_file_url:
                return None, "Browser navigation returned no response", None, False

            # Give JS deobfuscation / eval layers time to execute
            await asyncio.sleep(random.uniform(3.0, 5.0))

            # Screenshot: landing page (stage 1 — what the browser first shows)
            await _snap("01_landing")

            # Track whether a lure CTA button was already clicked
            cta_clicked = False

            # Wait for Turnstile widget to auto-resolve if present,
            # with a configurable timeout to prevent hanging forever.
            turnstile_result = await _wait_for_turnstile(
                page, timeout=turnstile_timeout,
            )

            if turnstile_result == "timeout":
                # Turnstile escalated to interactive — try fresh context
                logger.info(
                    "Turnstile timed out after %ds, attempting fresh context",
                    turnstile_timeout,
                )
                # Close current page, open fresh one (new CF session)
                await page.close()
                page = await browser.new_page(ignore_https_errors=True)
                page.set_default_timeout(timeout * 1000)
                page.set_default_navigation_timeout(timeout * 1000)
                await page.add_init_script(_STEALTH_JS)

                # Re-register network handlers on new page
                page.on("request", _on_request)
                page.on("response", _on_response)
                page.on("websocket", _on_websocket)
                page.on("framenavigated", _on_framenav)
                await page.route("**/ipinfo.io/**", _handle_ipinfo_route)

                nav_start_time = time.monotonic()
                response = await page.goto(url, wait_until="domcontentloaded")
                await asyncio.sleep(random.uniform(3.0, 5.0))

                # Second attempt at Turnstile (fresh session = managed mode)
                turnstile_result = await _wait_for_turnstile(page, timeout=turnstile_timeout)

            # Screenshot: after Turnstile/bot check (stage 2) — only if Turnstile was present
            if turnstile_result != "absent":
                await _snap("02_bot_check")

                # Post-Turnstile: click CTA buttons that gate the real content
                # (e.g. "Verify to Play" voicemail lures, device-code phish)
                if turnstile_result == "solved":
                    cta_clicked = await _click_lure_cta(page, on_email_gate=_snap_email_blank)
                    if cta_clicked:
                        await _snap("02b_post_cta")

            # Simulate minimal human behavior to pass behavioral checks
            await _simulate_human_behavior(page)

            # Wait for any post-challenge redirect or content load.
            # Use asyncio.wait_for to enforce a hard deadline — Playwright's
            # wait_for_load_state("networkidle") can hang indefinitely when
            # Turnstile/CAPTCHA scripts keep polling.
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=15,
                )

            # Give anti-analysis JS time to run its scoring
            await asyncio.sleep(random.uniform(2.0, 4.0))

            # Attempt to bypass custom anti-bot verification gates
            elapsed = asyncio.get_event_loop().time() - start_time
            timeout_remaining = timeout - elapsed
            if timeout_remaining > 15:
                gate_found = await _attempt_bot_gate_bypass(
                    page, timeout_remaining,
                )
                if gate_found:
                    logger.info(
                        "Bot gate interaction completed: type=%s, final URL: %s",
                        gate_found, page.url,
                    )
                    # The honey email was typed and submitted inside the
                    # bypass, so the final domain was reached by
                    # interaction — same signal _click_lure_cta carries.
                    if gate_found == "email_gate":
                        cta_clicked = True

            # General CTA click — catches pages with no Turnstile and
            # no bot gate (QR code landers, link-through pages), or pages
            # where the gate resolved and revealed a CTA.
            if not cta_clicked:
                cta_clicked = await _click_lure_cta(page, on_email_gate=_snap_email_blank)
                if cta_clicked:
                    await _snap("02c_lure_cta")

            # Wait for final content to settle
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=15,
                )

            # Poll until the page stops changing before capturing.  This
            # replaces a fixed sleep + a narrow JS-loader-stub check that
            # missed interstitials which are large or lack document.write
            # (spinner pages, "Preparing secure session", "Checking…",
            # post-email-gate redirects, framework SPAs).  Stability-based
            # so it needs no phish-specific markers; loading text only
            # extends patience.
            await _settle_final_page(page)

            # Post-settle email-gate fill.  Many lures reveal the "enter
            # the email this was sent to" gate only on the *final* page —
            # after the CTA click or a client-side redirect (the DocuSign
            # /docusign-agreement-signature step machine is the canonical
            # case).  The single _fill_email_gate attempt inside
            # _click_lure_cta already ran on an earlier page that didn't
            # show the gate yet, so fill + submit it here too and re-settle
            # so the honey credential actually reaches the form.  Bounded
            # to a couple of iterations for multi-step gates.
            for _gate_attempt in range(2):
                gate = await _fill_email_gate(page, on_gate=_snap_email_blank)
                if gate != GATE_FILLED:
                    break
                cta_clicked = True  # interaction-driven — suppresses rerender
                await _snap("02d_email_gate")
                await _submit_email_gate(page)
                with contextlib.suppress(TimeoutError, Exception):
                    await asyncio.wait_for(
                        page.wait_for_load_state("networkidle"), timeout=15,
                    )
                await _settle_final_page(page)

            # Screenshot: final phishing page (stage 3)
            await _snap("03_phish")

            # Capture final page content
            content = await page.content()
            final_url = page.url

            # Visible text of the final page — feeds stage role
            # classification (bot-check / interstitial / post-submit
            # markers read better off innerText than raw HTML).
            final_visible_text = ""
            with contextlib.suppress(Exception):
                final_visible_text = (await page.inner_text("body"))[:8000]

            if not content or len(content) < 100:
                return None, "Browser captured empty or minimal page content", None, False

            # Save HTML to disk
            filename = "page.html"
            filepath = dest_path / filename
            filepath.write_text(content, encoding="utf-8")

            # Save captured sub-resources
            saved_resources = 0
            manifest_entries: list[dict] = []
            # The main document itself — scanners should treat page.html as
            # originating from the final landing URL.
            manifest_entries.append({
                "filename": "page.html",
                "url": final_url or url,
                "status": None,
                "content_type": "text/html",
                "index": 0,
                "role": "final",
            })

            # Cross-origin redirect preservation.
            #
            # When the page navigates away from the original URL (cloak-and-
            # decoy gates, burned-token redirects, geo/ASN-based pivots) the
            # ``page.content()`` snapshot above holds the *final* DOM — often
            # an unrelated decoy site (temu.com, dhgate, etc.).  The original
            # URL's response body, captured by ``_on_response`` above, would
            # otherwise be dropped by the de-duplication branch below because
            # ``resp["url"] == url``.  That body is the gate HTML — the only
            # content with attribution value for the kit, since the decoy
            # landing is by definition noise.
            #
            # Save it as ``initial.html`` so IOC extraction, YARA, TLSH, and
            # the inspector view all see the gate.  The ``role`` field on
            # the manifest entry lets downstream code distinguish "what we
            # asked for" from "where we ended up."
            saved_initial_html = False
            if final_url and final_url != url:
                initial_resp = next(
                    (
                        r for r in captured_responses
                        if r["url"] == url
                        and "html" in (r.get("content_type") or "").lower()
                    ),
                    None,
                )
                if initial_resp is not None:
                    try:
                        body = initial_resp["body"]
                        initial_path = dest_path / "initial.html"
                        if isinstance(body, bytes):
                            try:
                                initial_path.write_text(
                                    body.decode("utf-8", errors="replace"),
                                    encoding="utf-8",
                                )
                            except Exception:
                                initial_path.write_bytes(body)
                        else:
                            initial_path.write_text(
                                str(body), encoding="utf-8",
                            )
                        manifest_entries.append({
                            "filename": "initial.html",
                            "url": url,
                            "status": initial_resp.get("status"),
                            "content_type": initial_resp.get(
                                "content_type", "text/html",
                            ),
                            "index": initial_resp.get("index", 0),
                            "request_id": initial_resp.get("request_id"),
                            "method": initial_resp.get("method"),
                            "timestamp": initial_resp.get("timestamp"),
                            "role": "initial",
                        })
                        saved_initial_html = True
                        logger.info(
                            "Preserved gate response as initial.html "
                            "(redirect: %s -> %s)",
                            url, final_url,
                        )
                    except Exception as e:
                        logger.debug(
                            "Failed to save initial.html for %s: %s", url, e,
                        )

            if captured_responses:
                resources_dir.mkdir(parents=True, exist_ok=True)
                for resp in captured_responses:
                    # Skip the final document — already saved as page.html.
                    if resp["url"] == final_url:
                        continue
                    # Skip the initial response if we promoted it to
                    # initial.html above (avoids a duplicate copy under
                    # _browser_resources/).
                    if saved_initial_html and resp["url"] == url:
                        continue
                    # Same-URL with no redirect: page.html already holds it.
                    if not saved_initial_html and resp["url"] == url:
                        continue
                    try:
                        res_filename = _sanitize_filename(
                            resp["url"], resp["index"],
                        )
                        # Add appropriate extension based on content type
                        ct = resp["content_type"].lower()
                        if "javascript" in ct and not res_filename.endswith(".js"):
                            res_filename += ".js"
                        elif "json" in ct and not res_filename.endswith(".json"):
                            res_filename += ".json"
                        elif "css" in ct and not res_filename.endswith(".css"):
                            res_filename += ".css"
                        elif "html" in ct and not any(
                            res_filename.endswith(e) for e in (".html", ".htm", ".php")
                        ):
                            res_filename += ".html"

                        res_path = resources_dir / res_filename
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
                        saved_resources += 1
                        manifest_entries.append({
                            "filename": f"_browser_resources/{res_filename}",
                            "url": resp["url"],
                            "status": resp.get("status"),
                            "content_type": resp.get("content_type", ""),
                            "index": resp["index"],
                            "request_id": resp.get("request_id"),
                            "method": resp.get("method"),
                            "timestamp": resp.get("timestamp"),
                        })
                    except Exception as e:
                        logger.debug(
                            "Failed to save resource %s: %s", resp["url"], e,
                        )

            # Write the resource manifest so the IOC scanner can correlate
            # each on-disk file back to the URL it came from.  Consumed by
            # ioc_engine.ResourceManifest.load().
            try:
                manifest_path = resources_dir / "_manifest.json"
                if resources_dir.exists() or manifest_entries:
                    resources_dir.mkdir(parents=True, exist_ok=True)
                    manifest_path.write_text(
                        json.dumps(manifest_entries, indent=2),
                        encoding="utf-8",
                    )
            except Exception as e:
                logger.debug("Failed to save resource manifest: %s", e)

            # Save network log as requests.json
            try:
                requests_path = dest_path / "requests.json"
                requests_path.write_text(
                    json.dumps(network_log, indent=2, default=str),
                    encoding="utf-8",
                )
            except Exception as e:
                logger.debug("Failed to save requests.json: %s", e)

            # Save the stage manifest (attack-flow segmentation).  One
            # entry per main-frame navigation, with per-stage body files
            # under _stages/.  Consumed by
            # darla.analysis.staging.segment_render at render finalise.
            try:
                stage_manifest, stage_bodies = _assemble_stages_manifest(
                    main_frame_navs, captured_responses,
                    final_url or url, content, final_visible_text,
                    screenshot_log,
                )
                if stage_manifest:
                    stages_dir = dest_path / "_stages"
                    stages_dir.mkdir(parents=True, exist_ok=True)
                    for rel, text in stage_bodies.items():
                        try:
                            (dest_path / rel).write_text(text, encoding="utf-8")
                        except OSError as we:
                            logger.debug("Failed to write %s: %s", rel, we)
                    (dest_path / "stages.json").write_text(
                        json.dumps(
                            {"stages": stage_manifest, "final_url": final_url},
                            indent=2, default=str,
                        ),
                        encoding="utf-8",
                    )
                    logger.info(
                        "Wrote stages.json (%d stages) for %s",
                        len(stage_manifest), url,
                    )
            except Exception as e:
                logger.debug("Failed to save stages.json: %s", e)

            # Save WebSocket frames as JSONL (one object per line).
            # Only written when at least one frame was captured so kits
            # without any wss:// traffic don't get a stub file.
            if ws_frames:
                try:
                    ws_path = dest_path / "websocket_frames.jsonl"
                    with ws_path.open("w", encoding="utf-8") as fh:
                        for frame in ws_frames:
                            fh.write(json.dumps(frame, default=str))
                            fh.write("\n")
                    logger.info(
                        "Captured %d WebSocket frame(s) → %s",
                        len(ws_frames), ws_path.name,
                    )
                except Exception as e:
                    logger.debug("Failed to save websocket_frames.jsonl: %s", e)

            logger.info(
                "Browser captured %d bytes from %s (final URL: %s, "
                "%d sub-resources, %d network events)",
                len(content), url, final_url,
                saved_resources, len(network_log),
            )
            # cta_clicked is True when a CTA was clicked and/or the
            # email gate was filled — i.e. the final domain was
            # reached by interaction, not a passive relay redirect.
            return filepath, "ok", final_url, cta_clicked

    except Exception as e:
        logger.error("Browser download failed for %s: %s", url, e)
        return None, f"Browser error: {type(e).__name__}: {e}", None, False


async def _wait_for_turnstile(page, timeout: int = 30) -> str:
    """Wait for Cloudflare Turnstile CAPTCHA and attempt to solve it.

    Returns:
        "solved" — Turnstile was present and resolved
        "absent" — No Turnstile widget on page
        "timeout" — Turnstile present but not solved within timeout
        "error" — Exception during handling
    """
    try:
        # Check if page has a Turnstile widget at all
        has_turnstile = await page.evaluate("""
            () => !!document.querySelector('.cf-turnstile, [data-sitekey]')
        """)
        if not has_turnstile:
            return "absent"

        logger.info("Turnstile widget found on page")

        # Give managed-mode a few seconds to auto-resolve
        await asyncio.sleep(random.uniform(2.5, 4.0))

        # Check if already solved (response token populated)
        if await _turnstile_solved(page):
            logger.info("Turnstile auto-resolved (managed mode)")
            await _wait_after_turnstile(page)
            return "solved"

        # Find the Turnstile iframe via page.frames (not frame_locator)
        frame_element = None
        for frame in page.frames:
            if "challenges.cloudflare.com" in frame.url:
                try:
                    frame_element = await frame.frame_element()
                    break
                except Exception:
                    continue

        if frame_element:
            box = await frame_element.bounding_box()
            if box:
                click_x = box["x"] + box["width"] / 9
                click_y = box["y"] + box["height"] / 2
                logger.info(
                    "Clicking Turnstile iframe at (%.0f, %.0f)",
                    click_x, click_y,
                )
                await page.mouse.click(click_x, click_y)
                await asyncio.sleep(random.uniform(1.5, 3.0))
        else:
            widget = await page.query_selector(
                ".cf-turnstile, [data-sitekey]"
            )
            if widget:
                box = await widget.bounding_box()
                if box:
                    click_x = box["x"] + 25
                    click_y = box["y"] + box["height"] / 2
                    logger.info(
                        "Clicking Turnstile wrapper at (%.0f, %.0f)",
                        click_x, click_y,
                    )
                    await page.mouse.click(click_x, click_y)
                    await asyncio.sleep(random.uniform(1.5, 3.0))
                else:
                    logger.warning(
                        "Turnstile widget found but has no bounding box — "
                        "will poll for auto-resolve",
                    )
            else:
                logger.warning(
                    "Turnstile widget present but no clickable element found — "
                    "will poll for auto-resolve",
                )

        # Poll for the response token with a hard timeout
        poll_deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < poll_deadline:
            if await _turnstile_solved(page):
                logger.info("Turnstile solved after click")
                await _wait_after_turnstile(page)
                return "solved"
            await asyncio.sleep(1.0)

        logger.warning(
            "Turnstile not solved within %ds timeout", timeout,
        )
        return "timeout"

    except Exception as e:
        logger.warning("Turnstile handling error: %s", e)
        return "error"


async def _turnstile_solved(page) -> bool:
    """Check if Turnstile response token has been populated."""
    return await page.evaluate("""
        () => {
            const resp = document.querySelector(
                'input[name="cf-turnstile-response"]'
            );
            return !!(resp && resp.value && resp.value.length > 0);
        }
    """)


async def _wait_after_turnstile(page) -> None:
    """Wait for post-Turnstile navigation or content swap."""
    await asyncio.sleep(random.uniform(2.0, 4.0))
    with contextlib.suppress(TimeoutError, Exception):
        await asyncio.wait_for(
            page.wait_for_load_state("networkidle"),
            timeout=10,
        )


async def _simulate_human_behavior(page) -> None:
    """Simulate minimal mouse movement and scrolling.

    Many phishing kits track mouse/keyboard events and score the interaction.
    Even basic movement with randomized timing can pass simple behavioral checks.
    """
    try:
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        w, h = viewport["width"], viewport["height"]

        # Random mouse movements with natural-looking coordinates
        for _ in range(random.randint(3, 6)):
            x = random.randint(int(w * 0.1), int(w * 0.9))
            y = random.randint(int(h * 0.1), int(h * 0.7))
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.1, 0.4))

        # Small scroll
        await page.mouse.wheel(0, random.randint(50, 200))
        await asyncio.sleep(random.uniform(0.3, 0.8))

    except Exception:
        # Non-fatal — page may not support these interactions
        pass


# Fields a lure uses to ask "which email got the document?".  Case-
# insensitive attribute matches cover name="userEmail", id="mail", etc.
# The placeholder/aria variants catch kits that label the field only
# visually ("you@company.com", aria-label="Work e-mail").
_EMAIL_GATE_SELECTOR = (
    'input[type="email"], input[autocomplete="email"], '
    'input[autocomplete="username"], input[name*="mail" i], '
    'input[id*="mail" i], input[placeholder*="mail" i], '
    'input[aria-label*="mail" i], input[name*="recipient" i], '
    'input[id*="recipient" i], input[placeholder*="@"]'
)
_TEXT_INPUT_TYPES = {"", "text", "email"}


GATE_NONE, GATE_FILLED, GATE_UNFILLED = "none", "filled", "unfilled"


async def _submit_email_gate(page) -> None:
    """Submit the current email-gate form after it's been filled.

    Clicks a submit/continue-style control if one is present, otherwise
    presses Enter (single-input gates submit on Enter).  Best-effort —
    any failure is swallowed so the render still captures the page.
    """
    clicked = False
    with contextlib.suppress(Exception):
        clicked = await page.evaluate("""
            () => {
                const els = document.querySelectorAll(
                    'button, input[type=submit], [role=button], a[href]'
                );
                for (const b of els) {
                    if (b.type === 'submit') { b.click(); return true; }
                    const t = ((b.value || '') + ' ' + (b.textContent || ''))
                        .trim().toLowerCase();
                    if (/^(continue|next|submit|verify|proceed|view|access|sign ?in|open)/.test(t)) {
                        b.click();
                        return true;
                    }
                }
                return false;
            }
        """)
    if not clicked:
        with contextlib.suppress(Exception):
            await page.keyboard.press("Enter")


async def _shares_form_with_password(field) -> bool:
    """True when this input sits in the same form as a password field.

    Distinguishes an email *gate* (email field alone, unlocks the next
    stage) from the credential harvester itself (email + password).
    Falls back to a document-wide check when the input is not inside a
    ``<form>`` — kits frequently post via JS with no form element.
    """
    try:
        return bool(await field.evaluate(
            """(el) => {
                const scope = el.form || el.closest('form') || document;
                return !!scope.querySelector('input[type="password"]');
            }"""
        ))
    except Exception:
        return False


async def _fill_email_gate(page, on_gate=None) -> str:
    """Type the honey credential into a visible, empty email field.

    Email-gated lures validate the address server-side against the one the
    lure was sent to; clicking "Continue" on an empty field only earns
    "Please enter the correct email." and the credential page is never
    captured.  Returns ``GATE_FILLED``, ``GATE_NONE`` (no gate), or
    ``GATE_UNFILLED`` (gate present, no ``PK_HONEY_EMAIL`` configured —
    the caller must not submit it blank).

    A field sharing a form with a password input is skipped: that is the
    credential harvester we came to capture, not a gate, and typing +
    submitting there would navigate off the page before it is saved.

    ``on_gate`` is an optional async callback invoked once, the moment an
    empty fillable gate is found and *before* anything is typed — so the
    caller can screenshot the blank email-entry landing as the victim
    first saw it.
    """
    from darla.config import get_settings

    honey_email = get_settings().honey_email
    try:
        fields = await page.query_selector_all(_EMAIL_GATE_SELECTOR)
    except Exception:
        return GATE_NONE
    for field in fields:
        try:
            input_type = (await field.get_attribute("type") or "").lower()
            if input_type not in _TEXT_INPUT_TYPES:
                continue
            if not await field.is_visible() or not await field.is_editable():
                continue
            if (await field.input_value()).strip():
                continue
            if await _shares_form_with_password(field):
                # The credential harvester (email + password), not a gate —
                # leave it for capture, don't fill/submit or snap a "blank".
                continue
            if on_gate is not None:
                with contextlib.suppress(Exception):
                    await on_gate()
            if not honey_email:
                logger.info(
                    "Lure email gate detected but PK_HONEY_EMAIL is unset — "
                    "not submitting it",
                )
                return GATE_UNFILLED
            await field.click()
            await field.type(honey_email, delay=random.randint(40, 110))
            await asyncio.sleep(random.uniform(0.3, 0.8))
            logger.info("Filled lure email gate with the honey credential")
            return GATE_FILLED
        except Exception:
            continue
    return GATE_NONE


async def _click_lure_cta(page, on_email_gate=None) -> bool:
    """Click a prominent CTA button/link that gates the real phishing content.

    Covers multiple lure types:
    - Post-Turnstile voicemail/device-code phish ("Verify to Play")
    - QR code landing pages ("Open Document Here", "View PDF")
    - Generic click-through lures ("Continue", "Proceed")
    - Email gates ("Enter the email that got the document") — the honey
      credential is typed first, then the CTA (or Enter) submits it

    ``on_email_gate`` is forwarded to :func:`_fill_email_gate` so the
    caller can capture the blank email-entry landing before it's filled.

    Returns True if a CTA was found and clicked (or a filled gate submitted).
    """
    gate = await _fill_email_gate(page, on_gate=on_email_gate)
    if gate == GATE_UNFILLED:
        return False
    email_filled = gate == GATE_FILLED
    try:
        cta = await page.evaluate("""
            () => {
                const actionPatterns = [
                    /play.*voicemail/i, /verify to /i, /listen.*message/i,
                    /access.*voicemail/i, /^continue$/i, /^proceed$/i,
                    /^play$/i, /^listen$/i, /^play now$/i, /^listen now$/i,
                    /^open document/i, /^view pdf/i, /^view document/i,
                    /^open file/i, /^download document/i, /^open link/i,
                    /^view file/i, /^open here$/i,
                ];
                const candidates = document.querySelectorAll(
                    'button, a[href], [role="button"], [class*="btn"], '
                    + '[class*="call-action"], [class*="cta"]'
                );
                for (const el of candidates) {
                    const text = (el.textContent || '').trim();
                    if (text.length < 2 || text.length > 80) continue;
                    const rect = el.getBoundingClientRect();
                    // Only consider visible, prominent buttons
                    if (rect.width < 80 || rect.height < 25) continue;
                    if (rect.top < 0 || rect.left < 0) continue;
                    const style = getComputedStyle(el);
                    if (style.display === 'none' || style.visibility === 'hidden') continue;
                    if (parseFloat(style.opacity) < 0.1) continue;
                    for (const pat of actionPatterns) {
                        if (pat.test(text)) {
                            return {
                                selector: el.id ? '#' + CSS.escape(el.id)
                                    : (el.className && typeof el.className === 'string' && el.className.trim())
                                        ? el.tagName.toLowerCase() + '.' + CSS.escape(el.className.trim().split(/\\s+/)[0])
                                        : el.tagName.toLowerCase(),
                                text: text.substring(0, 60),
                                x: rect.x + rect.width / 2,
                                y: rect.y + rect.height / 2,
                            };
                        }
                    }
                }
                return null;
            }
        """)

        if not cta:
            if email_filled:
                # Gate without a recognised button ("Next", an icon, ...):
                # submit the form the way a user would.
                await page.keyboard.press("Enter")
                with contextlib.suppress(TimeoutError, Exception):
                    await page.wait_for_load_state("domcontentloaded", timeout=10_000)
                return True
            return False

        logger.info("Lure CTA detected: %r (selector=%s)", cta["text"], cta["selector"])

        # Natural mouse approach to the button
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        start_x = random.randint(int(viewport["width"] * 0.3), int(viewport["width"] * 0.7))
        start_y = random.randint(int(viewport["height"] * 0.2), int(viewport["height"] * 0.5))
        await page.mouse.move(start_x, start_y)
        await asyncio.sleep(random.uniform(0.2, 0.5))

        # Move toward the button with intermediate steps
        target_x, target_y = cta["x"], cta["y"]
        steps = random.randint(3, 6)
        for i in range(1, steps + 1):
            frac = i / steps
            ix = start_x + (target_x - start_x) * frac + random.uniform(-3, 3)
            iy = start_y + (target_y - start_y) * frac + random.uniform(-3, 3)
            await page.mouse.move(ix, iy)
            await asyncio.sleep(random.uniform(0.03, 0.1))

        await asyncio.sleep(random.uniform(0.1, 0.3))

        # Strip target="_blank" so the click navigates in the same tab
        # instead of opening a new tab that Playwright won't follow.
        with contextlib.suppress(Exception):
            await page.evaluate("""
                (sel) => {
                    const el = document.querySelector(sel);
                    if (el && el.target === '_blank') {
                        el.removeAttribute('target');
                    }
                    // Also strip any anchors inside the button
                    if (el) {
                        for (const a of el.querySelectorAll('a[target="_blank"]')) {
                            a.removeAttribute('target');
                        }
                    }
                }
            """, cta["selector"])

        # Click
        try:
            el = await page.query_selector(cta["selector"])
            if el:
                await el.click()
            else:
                await page.mouse.click(target_x, target_y)
        except Exception:
            await page.mouse.click(target_x, target_y)

        # Wait for post-click navigation or content change
        with contextlib.suppress(TimeoutError, Exception):
            await asyncio.wait_for(
                page.wait_for_load_state("networkidle"),
                timeout=10,
            )

        await asyncio.sleep(random.uniform(1.0, 2.0))
        logger.info("Lure CTA clicked: %r", cta["text"])
        return True

    except Exception as e:
        logger.debug("Lure CTA check failed: %s", e)
        return False


async def _detect_bot_gate(page) -> dict | None:
    """Detect common anti-bot verification gates on the page.

    Runs as a single ``page.evaluate`` whose layers are ordered
    cheapest-first and short-circuit on the first match, so the common
    case (no gate) pays only for a handful of CSS attribute selectors:

      L1  class/id token match for fake-captcha widgets — one
          ``querySelector``, no layout, no text.  High confidence:
          legitimate sites don't name login-form elements
          ``captcha-box``/``captcha-btn``.  Catches the AITM cred-relay
          pattern (``#captcha-wrapper`` wrapping a click-to-continue
          gate that unlocks a credential harvester + ``wss://`` relay).
      L2  class/id/ARIA token match for slide-to-unlock and
          press-and-hold widgets.  Same cost as L1, and it has to run
          before any text layer: these need a drag / long-press, so
          classifying one as a plain ``verify_button`` means clicking a
          handle that ignores clicks and stalling on the gate.
      L3  one ``document.body.innerText`` read — forces layout, so it
          happens once and every later layer reuses the result.
      L4  text/ARIA scan over button-ish candidates, bounded by the
          candidate selector rather than the whole DOM.
      L5  CSS-affordance scan: elements that only *look* clickable
          (``[class*="btn"]``, ``tabindex``, ``role``, ``aria-pressed``,
          ``data-action``, ``draggable``) sitting next to gate text.
          Catches kits whose gate element carries no vocabulary of its
          own — an icon, a bare styled div.
      L6  div/span checkbox sweep — ``getComputedStyle`` per node.
      L7  hidden challenge form fields with a prominent clickable.
      L8  POST form + hidden input + a full pointer sweep — the most
          expensive path, so it stays last.
      L9  honey-email entry gate.  Cheap to test but deliberately last
          on *priority*, not cost: any real bot gate on the same page
          outranks it, and an email field sharing a form with a
          password input is the credential harvester we came to
          capture, not a gate to click through.

    Returns gate metadata or None if no gate detected.  ``type`` tells
    the bypass how to interact: ``slider_gate`` drags, ``hold_gate``
    long-presses, ``email_gate`` types the honey credential, every
    other type clicks.
    """
    try:
        return await page.evaluate(r"""
            (emailSel) => {
                function makeSelector(el) {
                    if (el.id) return '#' + CSS.escape(el.id);
                    if (el.className && typeof el.className === 'string') {
                        const cls = el.className.trim().split(/\s+/)[0];
                        if (cls) return el.tagName.toLowerCase() + '.' + CSS.escape(cls);
                    }
                    return el.tagName.toLowerCase();
                }

                function isVisible(el) {
                    if (!el) return false;
                    const cs = window.getComputedStyle(el);
                    if (cs.display === 'none' || cs.visibility === 'hidden') return false;
                    if (parseFloat(cs.opacity) < 0.1) return false;
                    const r = el.getBoundingClientRect();
                    return r.width > 0 && r.height > 0;
                }

                function boxOf(el) {
                    const r = el.getBoundingClientRect();
                    return { x: r.x, y: r.y, width: r.width, height: r.height };
                }

                // Everything a control shows a user.  Kits label the gate
                // via aria-label/title/data-text when the affordance is an
                // icon or a bare div, so textContent alone under-matches.
                function labelOf(el) {
                    const attr = (n) => (el.getAttribute ? (el.getAttribute(n) || '') : '');
                    return [
                        el.textContent || '',
                        el.value || '',
                        attr('aria-label'), attr('title'),
                        attr('placeholder'), attr('data-text'),
                    ].join(' ').replace(/\s+/g, ' ').trim();
                }

                // L2 vocabulary, reused by L3/L4/L5 to pick an interaction.
                const holdPats = [
                    /press\s*(?:and|&|\+)\s*hold/i,
                    /click\s*(?:and|&|\+)\s*hold/i,
                    /tap\s*(?:and|&|\+)\s*hold/i,
                    /touch\s*(?:and|&|\+)\s*hold/i,
                    /hold\s*(?:down\s*)?(?:the\s*)?(?:button|circle|icon|square)/i,
                    /hold\s*to\s*(?:unlock|open|access|continue|verify|view|proceed|confirm|download)/i,
                    /keep\s*(?:holding|pressing)/i,
                    /long[- ]press/i,
                ];
                const slidePats = [
                    /slide\s*to\s*(?:unlock|open|access|continue|verify|view|proceed|confirm|download)/i,
                    /swipe\s*to\s*(?:unlock|open|access|continue|verify|view|proceed|confirm|download)/i,
                    /drag\s*to\s*(?:unlock|open|access|continue|verify|view|proceed|confirm|download)/i,
                    /slide\s*(?:the\s*)?(?:slider|handle|button|arrow|puzzle)/i,
                    /drag\s*(?:the\s*)?(?:slider|handle|puzzle|piece)/i,
                    /move\s*the\s*slider/i,
                    /slide\s*(?:right|across)/i,
                    /swipe\s*right/i,
                ];
                const anyPat = (pats, s) => pats.some(p => p.test(s));

                // Copy that marks a "which address did this reach?" gate.
                // Required corroboration for the email probe: a burned
                // token drops us on a real decoy site (temu, dhgate), and
                // typing the honey address into its newsletter box would
                // leak the credential to an uninvolved third party.
                const emailLurePats = [
                    /e-?mail (?:address )?(?:this|the|that) (?:document|file|message|invoice|fax|voicemail)/i,
                    /(?:enter|confirm|verify) (?:your |the )?e-?mail (?:address )?to (?:view|access|open|continue|proceed|download|unlock)/i,
                    /e-?mail (?:that|which) (?:received|got)/i,
                    /(?:document|file|message) (?:was )?(?:sent|shared) to/i,
                    /to (?:view|access|open|download) (?:this|the) (?:document|file|message)/i,
                    /enter your e-?mail (?:below )?to continue/i,
                ];

                // An empty, visible email field that is not part of a
                // credential form.  A field sharing a form with a password
                // input is the harvester we came to capture, not a gate:
                // submitting it navigates away before the page is saved.
                function findEmailGateField(text) {
                    const candidates = [];
                    for (const f of document.querySelectorAll(emailSel)) {
                        const t = (f.getAttribute('type') || '').toLowerCase();
                        if (t && t !== 'text' && t !== 'email') continue;
                        if (f.disabled || f.readOnly) continue;
                        if (!isVisible(f)) continue;
                        if (f.value && f.value.trim()) continue;
                        const scope = f.form || f.closest('form') || document;
                        if (scope.querySelector('input[type="password"]')) continue;
                        candidates.push(f);
                    }
                    if (candidates.length === 0) return null;
                    if (anyPat(emailLurePats, text)) return candidates[0];
                    // No lure copy: accept only a bare gate lander — the
                    // page's single input, next to no navigation.
                    const inputs = [...document.querySelectorAll(
                        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]), '
                        + 'textarea, select'
                    )].filter(isVisible);
                    const links = document.querySelectorAll('a[href]');
                    if (inputs.length === 1 && links.length <= 2) return candidates[0];
                    return null;
                }

                function emailGateResult(f) {
                    return {
                        type: 'email_gate',
                        selector: makeSelector(f),
                        text: labelOf(f).substring(0, 80),
                        tagName: f.tagName,
                    };
                }

                // Builders for the two interaction-specific gate types.
                // Declared here because L1 can also land on a slider/hold
                // widget that happens to be captcha-named.
                function sliderResult(host, type) {
                    // The draggable handle, not the track: dragging the
                    // track's centre moves nothing.
                    let handle = host.querySelector(
                        '[class*="handle"], [class*="knob"], [class*="thumb"], '
                        + '[class*="slider-btn"], [class*="slide-btn"], '
                        + '[class*="drag"], [draggable="true"], [role="slider"], '
                        + 'button, input[type="range"]'
                    );
                    if (!handle) {
                        for (const d of host.querySelectorAll('*')) {
                            if (!isVisible(d)) continue;
                            const cs = window.getComputedStyle(d);
                            if (cs.cursor === 'pointer' || cs.cursor === 'grab'
                                || cs.cursor === 'move' || cs.cursor === 'ew-resize') {
                                handle = d;
                                break;
                            }
                        }
                    }
                    const target = handle || host;
                    return {
                        type: type,
                        selector: makeSelector(target),
                        host_selector: makeSelector(host),
                        text: labelOf(host).substring(0, 80),
                        tagName: target.tagName,
                        box: boxOf(target),
                        track: boxOf(host),
                        isRangeInput: target.tagName === 'INPUT'
                            && (target.getAttribute('type') || '').toLowerCase() === 'range',
                    };
                }

                function holdResult(host, target) {
                    const el = target || host;
                    const raw = host.getAttribute('data-hold-duration')
                        || host.getAttribute('data-hold')
                        || host.getAttribute('data-duration') || '';
                    const parsed = parseInt(raw, 10);
                    return {
                        type: 'hold_gate',
                        selector: makeSelector(el),
                        host_selector: makeSelector(host),
                        text: labelOf(host).substring(0, 80),
                        tagName: el.tagName,
                        box: boxOf(el),
                        hold_ms: Number.isFinite(parsed) && parsed > 0 ? parsed : null,
                    };
                }

                // --- L1: class/id token signal for fake captcha gates ---
                // Target class/id substrings that legitimate sites don't use
                // on their login pages.  Attackers tend to copy open-source
                // click-captcha templates that preserve these class names.
                const captchaHost = document.querySelector(
                    '[class*="captcha"], [id*="captcha"], '
                    + '[class*="human-check"], [id*="human-check"], '
                    + '[class*="human-verif"], [id*="human-verif"], '
                    + '[class*="humancheck"], [class*="humanverif"], '
                    + '[class*="clickcaptcha"], [id*="clickcaptcha"], '
                    + '[class*="not-robot"], [class*="notrobot"], '
                    + '[class*="robot-check"], [class*="robotcheck"], '
                    + '[class*="verify-human"], [id*="verify-human"], '
                    + '[class*="verifyhuman"], [class*="human-test"]'
                );
                if (captchaHost && isVisible(captchaHost)) {
                    // A captcha-named host can still be a slider/hold widget
                    // ("slider-captcha"); honour the interaction its own
                    // label advertises before falling through to a click.
                    const hostLabel = labelOf(captchaHost);
                    if (anyPat(slidePats, hostLabel)) {
                        return sliderResult(captchaHost, 'slider_gate');
                    }
                    if (anyPat(holdPats, hostLabel)) {
                        return holdResult(captchaHost, null);
                    }
                    // Prefer an explicit button/role inside the host.
                    const explicitClickable = captchaHost.querySelector(
                        'button, [role="button"], input[type="submit"], [onclick], '
                        + '[role="checkbox"], input[type="checkbox"], '
                        + '[tabindex]:not([tabindex="-1"])'
                    );
                    // Else any cursor:pointer descendant — the whole gate
                    // div sometimes IS the clickable (onclick attached via
                    // addEventListener, which we can't see from the DOM).
                    let fallback = null;
                    if (!explicitClickable) {
                        const descendants = captchaHost.querySelectorAll('*');
                        for (const d of descendants) {
                            if (!isVisible(d)) continue;
                            const cs = window.getComputedStyle(d);
                            if (cs.cursor === 'pointer') {
                                fallback = d;
                                break;
                            }
                        }
                    }
                    const target = explicitClickable || fallback || captchaHost;
                    const text = (target.textContent || target.value || '')
                        .trim().substring(0, 80);
                    return {
                        type: 'fake_captcha_gate',
                        selector: makeSelector(target),
                        text: text,
                        tagName: target.tagName,
                        hasAutoSubmitForm: !!document.querySelector(
                            'form[method] input[type="hidden"]'
                        ),
                        host_selector: makeSelector(captchaHost),
                    };
                }

                // ---------------------------------------------------
                // L2: slide-to-unlock / press-and-hold widget tokens
                // ---------------------------------------------------
                // Same cost as L1 (one querySelector each) and it must
                // beat every text layer, because these gates ignore a
                // plain click — the bypass has to drag or long-press.
                const slideHost = document.querySelector(
                    '[class*="slide-to"], [id*="slide-to"], '
                    + '[class*="slidetounlock"], [id*="slidetounlock"], '
                    + '[class*="slide-unlock"], [class*="slideunlock"], '
                    + '[class*="swipe-to"], [id*="swipe-to"], '
                    + '[class*="drag-to"], [id*="drag-to"], '
                    + '[class*="slider-captcha"], [class*="slidercaptcha"], '
                    + '[class*="slide-verify"], [class*="slideverify"], '
                    + '[class*="puzzle-captcha"], [class*="puzzle-slider"], '
                    + '[aria-label*="slide to" i], [aria-label*="swipe to" i], '
                    + '[data-slide-to-unlock], [data-slider], '
                    + '[role="slider"], input[type="range"]'
                );
                if (slideHost && isVisible(slideHost)) {
                    return sliderResult(slideHost, 'slider_gate');
                }

                const holdHost = document.querySelector(
                    '[class*="press-and-hold"], [class*="press-hold"], '
                    + '[class*="presshold"], [id*="press-hold"], '
                    + '[class*="hold-to"], [id*="hold-to"], '
                    + '[class*="hold-btn"], [class*="holdbtn"], '
                    + '[class*="hold-button"], [class*="holdbutton"], '
                    + '[class*="long-press"], [class*="longpress"], '
                    + '[aria-label*="press and hold" i], [aria-label*="hold to" i], '
                    + '[data-hold], [data-hold-duration]'
                );
                if (holdHost && isVisible(holdHost)) {
                    const inner = holdHost.querySelector(
                        'button, [role="button"], [class*="btn"], '
                        + '[tabindex]:not([tabindex="-1"])'
                    );
                    return holdResult(holdHost, inner && isVisible(inner) ? inner : holdHost);
                }

                // ---------------------------------------------------
                // L3: one innerText read + gate vocabulary
                // ---------------------------------------------------
                // Hoisted so L4's skip-when-form-driven check and every
                // later layer reuse the single forced layout this costs.
                const pageText = document.body ? document.body.innerText : '';
                const gateTextPats = [
                    // "are you human" family
                    /prove you are human/i,
                    /prove you'?re (?:human|not a robot)/i,
                    /verify you'?re not a bot/i,
                    /verify (?:that )?you(?:'|a)?re (?:a )?human/i,
                    /confirm you'?re real/i,
                    /confirm.{0,3}humanit/i,
                    /confirm you are not a robot/i,
                    /are you (?:a )?human/i,
                    /i'?m not a robot/i,
                    /i am not a robot/i,
                    /i am.{0,3}human/i,
                    /i'?m (?:a )?human/i,
                    /not a robot/i,
                    /human (?:check|verification|challenge|test)/i,
                    /robot check/i,
                    /anti-?bot/i,
                    /bot protection/i,
                    /captcha/i,
                    // "security / verification" family
                    /security (?:check|verification|challenge)/i,
                    /verification required/i,
                    /additional verification/i,
                    /verify (?:your )?identity/i,
                    /verify (?:your )?(?:connection|request|access)/i,
                    /complete (?:the )?(?:security )?(?:check|challenge|verification)/i,
                    /checking.{0,10}browser/i,
                    /verifying (?:your )?(?:browser|connection|request|identity)/i,
                    /connection is secure/i,
                    /unusual traffic/i,
                    /suspicious activity/i,
                    // interstitial / "one more step" family
                    /one more step/i,
                    /just a moment/i,
                    /please wait while we (?:verify|check|prepare)/i,
                    /this (?:process|check) is automatic/i,
                    /you will be redirected (?:shortly|automatically)/i,
                    /before (?:you )?(?:continue|proceed|access)/i,
                    // explicit instruction family
                    /click.{0,10}(box|button|checkbox).{0,10}verify/i,
                    /click (?:the )?(?:box|checkbox|button) below/i,
                    /tap (?:the )?(?:box|checkbox|button) (?:below|to)/i,
                    /press (?:the )?button (?:below|to)/i,
                    /verify to (?:continue|proceed|view|access|download|open)/i,
                    // slide / hold instructions
                    ...slidePats,
                    ...holdPats,
                    // non-English kit copy seen in the wild
                    /no soy un robot/i,
                    /je ne suis pas un robot/i,
                    /ich bin kein roboter/i,
                    /n(?:a|ã)o sou um rob(?:o|ô)/i,
                    /verificaci(?:o|ó)n de seguridad/i,
                ];
                const hasGateText = gateTextPats.some(p => p.test(pageText));
                const pageWantsSlide = anyPat(slidePats, pageText);
                const pageWantsHold = anyPat(holdPats, pageText);

                // Strategy-priority guard: if the page has a hidden form
                // with submit-token fields AND a small clickable element
                // (checkbox-style div/span), the form is driven by the
                // checkbox click, not by any "Verify" anchor that might
                // also be on the page.  Skip L4 / L5 in that case so
                // L6 / L8 can return the right element.
                //
                // Without this, kits with both a "Verify" link and a
                // verifyCheckbox (e.g. teamfiledocumet.com pattern) match
                // L4 first; we click the link, the gate JS clears
                // the wrapper but never submits the form, and the kit
                // gets stuck on the gate page (TLSH-matched as ancestor
                // duplicate).
                const submitTokenForm = document.querySelector(
                    'form[method] input[type="hidden"][name*="token"], '
                    + 'form[method] input[type="hidden"][name*="captcha"], '
                    + 'form[method] input[type="hidden"][name*="nonce"], '
                    + 'form[method] input[type="hidden"][name*="challenge"]'
                );
                let smallClickable = null;
                if (submitTokenForm) {
                    const sweep = document.querySelectorAll('div, span');
                    for (const d of sweep) {
                        const cs = window.getComputedStyle(d);
                        const r = d.getBoundingClientRect();
                        if (cs.cursor === 'pointer'
                            && r.width >= 12 && r.width <= 60
                            && r.height >= 12 && r.height <= 60
                            && cs.display !== 'none') {
                            smallClickable = d;
                            break;
                        }
                    }
                }
                const skipVerifyButtonStrategy = !!(
                    submitTokenForm && hasGateText && smallClickable
                );

                // An unfilled honey-email field on a page with no bot-gate
                // vocabulary means the address itself is the gate.  It is
                // validated server-side against the lure recipient, so it
                // has to be typed before any "Next"/"Continue" is pressed
                // — otherwise L4 matches the button, clicks it, and the
                // kit answers "please enter the correct email".  Routing
                // it as email_gate hands the page to _click_lure_cta,
                // which fills first and then submits.
                if (!hasGateText) {
                    const earlyEmail = findEmailGateField(pageText);
                    if (earlyEmail) return emailGateResult(earlyEmail);
                }

                // ---------------------------------------------------
                // L4: text/ARIA scan over button-ish candidates
                // ---------------------------------------------------
                const candidates = [
                    ...document.querySelectorAll(
                        'button, a, input[type="button"], input[type="submit"], '
                        + '[role="button"], [onclick], div[class*="btn"], span[class*="btn"], '
                        + '[class*="call-action"], [class*="cta"], '
                        + '[role="checkbox"], [role="switch"], label[for], summary'
                    )
                ];

                const verifyPatterns = [
                    /^verify$/i, /^verify now$/i, /^verify you are human$/i,
                    /^verify me$/i, /^verify human$/i, /^verify my browser$/i,
                    /^check$/i, /^continue$/i, /^i'?m not a robot$/i,
                    /^i am not a robot$/i, /^i'?m human$/i, /^i am human$/i,
                    /^yes,? i'?m human$/i,
                    /^press & hold$/i, /^click to continue$/i,
                    /^confirm$/i, /^confirm you are human$/i,
                    /^human verification$/i, /^security check$/i,
                    /^click to verify/i, /^verify your browser/i,
                    /^verify to /i, /play.*voicemail/i, /listen.*message/i,
                    /access.*voicemail/i, /^play now$/i, /^listen now$/i,
                    /^click here to (?:verify|continue|proceed|access)/i,
                    /^tap to (?:verify|continue|proceed|unlock)/i,
                    /^press to (?:verify|continue|proceed|unlock)/i,
                    /^start (?:the )?(?:verification|challenge|check)$/i,
                    /^begin verification$/i,
                    /^complete (?:the )?(?:verification|challenge|check)$/i,
                    /^prove you'?re human$/i, /^prove you are human$/i,
                    /^verify (?:your )?identity$/i,
                    /^unlock$/i, /^unlock (?:now|document|file|access|page)/i,
                    /^continue to (?:site|page|document|file)/i,
                    /^proceed$/i, /^proceed to /i, /^next$/i,
                    /^verify (?:&|and) continue$/i,
                ];

                if (!skipVerifyButtonStrategy) {
                    for (const el of candidates) {
                        const text = labelOf(el);
                        if (text.length > 60 || text.length < 3) continue;
                        // Interaction-changing vocabulary wins: a control
                        // labelled "Slide to unlock" must not be clicked.
                        if (anyPat(slidePats, text)) {
                            const host = el.parentElement && isVisible(el.parentElement)
                                ? el.parentElement : el;
                            return sliderResult(host, 'slider_gate');
                        }
                        if (anyPat(holdPats, text)) {
                            return holdResult(el, el);
                        }
                        for (const pat of verifyPatterns) {
                            if (pat.test(text)) {
                                return {
                                    type: 'verify_button',
                                    selector: makeSelector(el),
                                    text: text,
                                    tagName: el.tagName,
                                };
                            }
                        }
                    }
                }

                // ---------------------------------------------------
                // L5: CSS-affordance scan next to gate text
                // ---------------------------------------------------
                // Kits whose gate element has no vocabulary at all: an
                // icon, an empty styled div, a tabindex'd span.  Only
                // runs once L3 confirmed gate text, and only accepts a
                // candidate that is labelled, inside a verification-named
                // container, or the page's single affordance — otherwise
                // this would happily click site navigation.
                if (hasGateText && !skipVerifyButtonStrategy) {
                    const affordances = [...document.querySelectorAll(
                        '[tabindex]:not([tabindex="-1"]), '
                        + '[class*="btn"], [class*="button"], [id*="btn"], '
                        + '[role="button"], [role="checkbox"], [role="switch"], '
                        + '[aria-pressed], [aria-checked], [onclick], '
                        + '[data-action], [data-toggle], [data-target], [jsaction], '
                        + 'label[for], input[type="checkbox"], [draggable="true"]'
                    )].filter(el => {
                        if (!isVisible(el)) return false;
                        const r = el.getBoundingClientRect();
                        return r.width >= 14 && r.height >= 14
                            && r.width <= 640 && r.height <= 240
                            && r.top >= 0 && r.top < 4000;
                    });

                    const containerSel = '[class*="verif"], [id*="verif"], '
                        + '[class*="captcha"], [class*="human"], [class*="robot"], '
                        + '[class*="challenge"], [class*="gate"], [class*="check"]';
                    let best = null;
                    let bestScore = 0;
                    for (const el of affordances) {
                        const label = labelOf(el);
                        let score = 0;
                        if (anyPat(slidePats, label) || anyPat(holdPats, label)) score = 4;
                        else if (gateTextPats.some(p => p.test(label))) score = 3;
                        else if (el.closest(containerSel)) score = 2;
                        if (score > bestScore) { best = el; bestScore = score; }
                    }
                    // Nothing labelled or containerised: accept a lone
                    // affordance.  The gate text already established that
                    // this page is a gate and there is nothing else to hit.
                    if (!best && affordances.length === 1) {
                        best = affordances[0];
                        bestScore = 1;
                    }

                    if (best) {
                        const label = labelOf(best);
                        if (anyPat(slidePats, label) || (pageWantsSlide && bestScore < 3)) {
                            const host = best.parentElement && isVisible(best.parentElement)
                                ? best.parentElement : best;
                            return sliderResult(host, 'slider_gate');
                        }
                        if (anyPat(holdPats, label) || (pageWantsHold && bestScore < 3)) {
                            return holdResult(best, best);
                        }
                        const tag = best.tagName.toLowerCase();
                        const role = (best.getAttribute('role') || '').toLowerCase();
                        const isCheckbox = role === 'checkbox' || role === 'switch'
                            || tag === 'label'
                            || (tag === 'input'
                                && (best.getAttribute('type') || '').toLowerCase() === 'checkbox');
                        return {
                            type: isCheckbox ? 'checkbox_gate' : 'affordance_gate',
                            selector: makeSelector(best),
                            text: (label || pageText).substring(0, 80).trim(),
                            tagName: best.tagName,
                            hasAutoSubmitForm: !!document.querySelector(
                                'form[method] input[type="hidden"]'
                            ),
                        };
                    }
                }

                // ---------------------------------------------------
                // L6: div/span checkbox sweep (getComputedStyle heavy)
                // ---------------------------------------------------
                if (hasGateText) {
                    const clickables = [...document.querySelectorAll(
                        'div[class*="check"], div[class*="target"], '
                        + 'div[class*="circle"], div[class*="square"], '
                        + 'span[class*="check"], span[class*="target"], '
                        + '[style*="cursor: pointer"], [style*="cursor:pointer"]'
                    )].filter(el => {
                        const r = el.getBoundingClientRect();
                        return r.width >= 12 && r.width <= 60
                            && r.height >= 12 && r.height <= 60
                            && r.width > 0 && r.height > 0;
                    });

                    if (clickables.length === 0) {
                        const containers = document.querySelectorAll(
                            '[class*="verif"], [class*="captcha"], [class*="check"], '
                            + '[class*="human"], [class*="premium-card"]'
                        );
                        for (const container of containers) {
                            const kids = container.querySelectorAll('div, span');
                            for (const kid of kids) {
                                const cs = window.getComputedStyle(kid);
                                const r = kid.getBoundingClientRect();
                                if (cs.cursor === 'pointer'
                                    && r.width >= 12 && r.width <= 60
                                    && r.height >= 12 && r.height <= 60) {
                                    clickables.push(kid);
                                }
                            }
                        }
                    }

                    // Fallback: page-wide scan for any small cursor:pointer
                    // element.  Gate text is already confirmed so any small
                    // clickable is very likely the checkbox — handles kits
                    // with obfuscated CSS class names.
                    if (clickables.length === 0) {
                        const allEls = document.querySelectorAll('div, span');
                        for (const el of allEls) {
                            const cs = window.getComputedStyle(el);
                            const r = el.getBoundingClientRect();
                            if (cs.cursor === 'pointer'
                                && r.width >= 12 && r.width <= 60
                                && r.height >= 12 && r.height <= 60
                                && r.width > 0 && r.height > 0) {
                                clickables.push(el);
                                break;
                            }
                        }
                    }

                    if (clickables.length > 0) {
                        const el = clickables[0];
                        return {
                            type: 'checkbox_gate',
                            selector: makeSelector(el),
                            text: pageText.substring(0, 80).trim(),
                            tagName: el.tagName,
                            hasAutoSubmitForm: !!document.querySelector(
                                'form[method] input[type="hidden"]'
                            ),
                        };
                    }
                }

                // ---------------------------------------------------
                // L7: hidden challenge fields with a button
                // ---------------------------------------------------
                const challengeFields = document.querySelectorAll(
                    'input[type="hidden"][name*="nonce"], input[type="hidden"][name*="token"], '
                    + 'input[type="hidden"][name*="pow"], form[style*="display:none"]'
                );
                if (challengeFields.length > 0) {
                    const btns = [...document.querySelectorAll(
                        'button, input[type="submit"], [role="button"]'
                    )].filter(b => {
                        const r = b.getBoundingClientRect();
                        return r.width > 0 && r.height > 0;
                    });
                    if (btns.length >= 1) {
                        const el = btns[0];
                        return {
                            type: 'challenge_form',
                            selector: makeSelector(el),
                            text: (el.textContent || el.value || '').trim(),
                            tagName: el.tagName,
                        };
                    }
                }

                // ---------------------------------------------------
                // L8: POST form + hidden input + full pointer sweep
                // ---------------------------------------------------
                if (hasGateText) {
                    const form = document.querySelector('form[method]');
                    const hiddenInput = form
                        ? form.querySelector('input[type="hidden"]')
                        : null;
                    if (form && hiddenInput) {
                        const allDivs = [...document.querySelectorAll('div, span')];
                        for (const el of allDivs) {
                            const cs = window.getComputedStyle(el);
                            const r = el.getBoundingClientRect();
                            if (cs.cursor === 'pointer'
                                && r.width >= 12 && r.width <= 60
                                && r.height >= 12 && r.height <= 60) {
                                return {
                                    type: 'checkbox_gate',
                                    selector: makeSelector(el),
                                    text: pageText.substring(0, 80).trim(),
                                    tagName: el.tagName,
                                    hasAutoSubmitForm: true,
                                };
                            }
                        }
                    }
                }

                // ---------------------------------------------------
                // L9: honey-email entry gate (last by priority)
                // ---------------------------------------------------
                // Tail case: the page carries gate vocabulary but no gate
                // element matched above, and it has an email field.  The
                // pre-L4 probe already handled pages with no gate text.
                const emailField = findEmailGateField(pageText);
                if (emailField) return emailGateResult(emailField);

                return null;
            }
        """, _EMAIL_GATE_SELECTOR)
    except Exception as e:
        logger.warning("Bot gate detection error: %s", e)
        return None


async def _build_mouse_track(page) -> None:
    """Generate realistic mouse movement to satisfy movement-tracking gates."""
    try:
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        w, h = viewport["width"], viewport["height"]

        cx = random.randint(int(w * 0.2), int(w * 0.5))
        cy = random.randint(int(h * 0.2), int(h * 0.5))
        await page.mouse.move(cx, cy)
        await asyncio.sleep(random.uniform(0.3, 0.6))

        for _ in range(random.randint(8, 12)):
            cx += random.randint(-120, 120)
            cy += random.randint(-80, 80)
            cx = max(10, min(cx, w - 10))
            cy = max(10, min(cy, h - 10))
            await page.mouse.move(cx, cy)
            await asyncio.sleep(random.uniform(0.05, 0.2))

        await page.mouse.wheel(0, random.randint(30, 120))
        await asyncio.sleep(random.uniform(0.2, 0.5))

    except Exception:
        pass


# Upper bound on a single press-and-hold attempt.  Real gates fill in
# 2-5s; anything longer is a gate we aren't going to pass, and the hold
# is spending the shared per-page budget while it waits.
_MAX_HOLD_SECONDS = 8.0

# Gate types whose resolution is a form POST rather than an in-page
# challenge, so the bypass polls for navigation instead of for the gate
# text clearing.
_FORM_SUBMIT_GATE_TYPES = {"checkbox_gate", "fake_captcha_gate"}


async def _live_box(page, gate: dict) -> dict | None:
    """Re-measure the gate element, falling back to the detected box.

    Detection and interaction are separated by the mouse-track phase, so
    the layout may have shifted (fonts, lazy images, the gate's own
    entrance animation).
    """
    with contextlib.suppress(Exception):
        element = await page.query_selector(gate["selector"])
        if element:
            box = await element.bounding_box()
            if box and box.get("width") and box.get("height"):
                return box
    box = gate.get("box")
    if box and box.get("width") and box.get("height"):
        return box
    return None


async def _drag_slider_gate(page, gate: dict) -> bool:
    """Drag a slide-to-unlock handle from one end of its track to the other.

    Slider gates listen for ``mousedown`` → a run of ``mousemove`` →
    ``mouseup``; a plain click emits none of the intermediate moves, so
    the handle snaps back and the gate never resolves.  The drag is
    eased and jittered because these kits routinely reject a
    constant-velocity, perfectly horizontal path as synthetic.
    """
    box = await _live_box(page, gate)
    if not box:
        logger.warning("Slider gate handle not measurable — skipping drag")
        return False

    track = gate.get("track") or {}
    sx = box["x"] + box["width"] / 2
    sy = box["y"] + box["height"] / 2

    track_width = track.get("width") or 0
    if track_width > box["width"]:
        # Overshoot the track's right edge slightly; kits check the
        # handle actually reached the end, and clamp the excess.
        target_x = track["x"] + track_width - box["width"] / 2 + 12.0
    else:
        target_x = sx + max(240.0, box["width"] * 6)

    viewport = page.viewport_size or {"width": 1280, "height": 800}
    target_x = min(target_x, viewport["width"] - 4.0)
    if target_x <= sx:
        target_x = sx + 160.0

    try:
        await page.mouse.move(sx, sy)
        await asyncio.sleep(random.uniform(0.15, 0.35))
        await page.mouse.down()
        steps = random.randint(18, 28)
        for i in range(1, steps + 1):
            frac = i / steps
            # Ease-out: fast off the mark, decelerating into the end stop.
            eased = 1 - (1 - frac) ** 2
            await page.mouse.move(
                sx + (target_x - sx) * eased,
                sy + random.uniform(-1.5, 1.5),
            )
            await asyncio.sleep(random.uniform(0.012, 0.035))
        await asyncio.sleep(random.uniform(0.1, 0.25))
        await page.mouse.up()
        logger.info(
            "Dragged slider gate %.0fpx (%s)", target_x - sx, gate["selector"],
        )
    except Exception as e:
        logger.warning("Slider gate drag failed: %s", e)
        return False

    # ``input[type=range]`` sliders are often read on the ``change``
    # event rather than from pointer coordinates; a drag that lands a
    # pixel short leaves the value below max.  Pin it and re-fire.
    if gate.get("isRangeInput"):
        with contextlib.suppress(Exception):
            await page.evaluate(
                """(sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return;
                    el.value = el.max || '100';
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                }""",
                gate["selector"],
            )
    return True


async def _press_and_hold_gate(page, gate: dict) -> bool:
    """Hold the primary button down until the gate resolves or time runs out.

    Press-and-hold gates fill a progress ring over a fixed duration and
    reset on ``mouseup``, so a click registers as an aborted attempt.
    The hold honours a ``data-hold-duration`` hint when the kit exposes
    one and otherwise runs until the page reacts, capped so a gate that
    never resolves can't eat the whole budget.
    """
    box = await _live_box(page, gate)
    if not box:
        logger.warning("Hold gate element not measurable — skipping hold")
        return False

    hold_ms = gate.get("hold_ms")
    if hold_ms and 500 <= hold_ms <= _MAX_HOLD_SECONDS * 1000:
        # Kit-declared duration plus a margin so we outlast its timer.
        hold_for = hold_ms / 1000 + 0.8
    else:
        hold_for = random.uniform(3.5, 4.5)
    hold_for = min(hold_for, _MAX_HOLD_SECONDS)

    tx = box["x"] + box["width"] / 2
    ty = box["y"] + box["height"] / 2
    pre_url = page.url

    try:
        await page.mouse.move(tx, ty)
        await asyncio.sleep(random.uniform(0.15, 0.35))
        await page.mouse.down()
        deadline = time.monotonic() + hold_for
        while time.monotonic() < deadline:
            await asyncio.sleep(0.25)
            # A finger resting on a button still drifts a pixel or two;
            # some gates treat a perfectly static pointer as synthetic.
            with contextlib.suppress(Exception):
                await page.mouse.move(
                    tx + random.uniform(-1.2, 1.2),
                    ty + random.uniform(-1.2, 1.2),
                )
            if page.url != pre_url:
                break
        await page.mouse.up()
        logger.info(
            "Held gate element for %.1fs (%s)", hold_for, gate["selector"],
        )
        return True
    except Exception as e:
        logger.warning("Hold gate press failed: %s", e)
        with contextlib.suppress(Exception):
            await page.mouse.up()
        return False


async def _attempt_bot_gate_bypass(page, timeout_remaining: float) -> str | None:
    """Detect and attempt to bypass a custom anti-bot verification gate.

    Returns the gate type that was engaged, or None when no gate was
    detected.  ``slider_gate`` is dragged, ``hold_gate`` is long-pressed,
    ``email_gate`` is handed to the honey-credential filler, and every
    other type is clicked.
    """
    gate = await _detect_bot_gate(page)
    if not gate:
        # Debug: log why detection failed
        try:
            debug = await page.evaluate("""
                () => {
                    const t = (document.body ? document.body.innerText : '').substring(0, 200);
                    const vis = document.documentElement.style.visibility;
                    return { text_preview: t, visibility: vis, url: location.href };
                }
            """)
            logger.info(
                "Bot gate not detected — visibility=%s text_preview=%r url=%s",
                debug.get("visibility"), debug.get("text_preview", "")[:100],
                debug.get("url"),
            )
        except Exception:
            pass
        return None

    logger.info(
        "Bot gate detected: type=%s text=%r selector=%s",
        gate["type"], gate["text"], gate["selector"],
    )

    # An email gate is not a bot check — it is the honey-credential
    # path.  _click_lure_cta already fills the field and submits it
    # (button, or Enter when the kit's submit control is unlabelled).
    if gate["type"] == "email_gate":
        submitted = await _click_lure_cta(page)
        logger.info("Email gate handled (submitted=%s)", submitted)
        return "email_gate" if submitted else "email_gate_unsubmitted"

    # Phase 1: Build mouse movement track
    # Brief delay so page event listeners are fully attached before
    # generating mouse movement (PoW gates measure track length).
    await asyncio.sleep(random.uniform(0.5, 1.0))
    await _build_mouse_track(page)

    # Phase 2: Engage the gate with the interaction its type demands.
    pre_click_url = page.url

    if gate["type"] == "slider_gate":
        await _drag_slider_gate(page, gate)
        await _wait_for_gate_resolution(page, pre_click_url, timeout_remaining)
        return gate["type"]

    if gate["type"] == "hold_gate":
        await _press_and_hold_gate(page, gate)
        await _wait_for_gate_resolution(page, pre_click_url, timeout_remaining)
        return gate["type"]

    # Everything else is a click, with a natural mouse approach.
    try:
        element = await page.query_selector(gate["selector"])
        if not element and gate["type"] == "verify_button":
            for candidate in await page.query_selector_all(
                "button, [role='button'], a"
            ):
                text = (await candidate.text_content() or "").strip()
                if text and text.lower() == gate["text"].lower():
                    element = candidate
                    break

        if not element:
            logger.warning("Bot gate element not found after detection")
            return gate["type"]

        box = await element.bounding_box()
        if box:
            viewport = page.viewport_size or {"width": 1280, "height": 800}
            sx = random.randint(
                int(viewport["width"] * 0.3), int(viewport["width"] * 0.7),
            )
            sy = random.randint(
                int(viewport["height"] * 0.3), int(viewport["height"] * 0.6),
            )
            tx = box["x"] + box["width"] / 2
            ty = box["y"] + box["height"] / 2

            steps = random.randint(3, 5)
            for i in range(1, steps + 1):
                frac = i / steps
                mx = sx + (tx - sx) * frac + random.uniform(-8, 8)
                my = sy + (ty - sy) * frac + random.uniform(-5, 5)
                await page.mouse.move(mx, my)
                await asyncio.sleep(random.uniform(0.04, 0.12))

            await asyncio.sleep(random.uniform(0.15, 0.4))
            await page.mouse.click(tx, ty)
        else:
            await element.click()

        logger.info("Clicked bot gate element: type=%s", gate["type"])

    except Exception as e:
        logger.warning("Failed to click bot gate element: %s", e)
        return gate["type"]

    # Phase 3: Wait for resolution
    if gate.get("hasAutoSubmitForm") or gate["type"] in _FORM_SUBMIT_GATE_TYPES:
        await _wait_for_form_submit(page, pre_click_url, timeout_remaining)
    else:
        await _wait_for_gate_resolution(page, pre_click_url, timeout_remaining)

    return gate["type"]


async def _wait_for_gate_resolution(
    page, pre_click_url: str, timeout_remaining: float,
) -> None:
    """Wait for bot gate challenge resolution and subsequent navigation."""
    gate_timeout = min(30.0, max(5.0, timeout_remaining - 10.0))
    logger.info("Waiting up to %.0fs for bot gate resolution", gate_timeout)

    try:
        try:
            await page.wait_for_url(
                lambda url: url != pre_click_url,
                timeout=gate_timeout * 1000,
            )
            logger.info("Bot gate navigated to %s", page.url)
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return
        except Exception:
            pass

        gate_gone = await page.evaluate("""
            () => {
                const els = document.querySelectorAll(
                    'button, input[type="submit"], [role="button"], span, div'
                );
                const pat = /verify|verifying|check|checking|continue|not a robot|confirm|processing|please wait|slide to|swipe to|drag to|press (?:and|&) hold|hold to/i;
                for (const b of els) {
                    const text = (b.textContent || b.value || '').trim();
                    if (text.length > 100) continue;
                    if (pat.test(text)) return false;
                }
                return true;
            }
        """)
        if gate_gone:
            logger.info("Bot gate elements cleared — gate passed")
            await asyncio.sleep(random.uniform(1.0, 2.0))
        else:
            # Gate text still present — could be PoW still computing.
            # Poll until it clears or we run out of time.
            logger.info(
                "Gate text still present — polling for PoW completion "
                "(up to %.0fs remaining)",
                gate_timeout,
            )
            import time as _time

            poll_deadline = _time.monotonic() + min(gate_timeout, 30.0)
            pow_passed = False
            while _time.monotonic() < poll_deadline:
                await asyncio.sleep(3.0)

                # Check if URL changed (PoW redirected)
                if page.url != pre_click_url:
                    logger.info("PoW redirected to %s", page.url)
                    pow_passed = True
                    break

                # Re-check if gate text disappeared
                still_present = await page.evaluate("""
                    () => {
                        const els = document.querySelectorAll(
                            'button, input[type="submit"], [role="button"], span, div'
                        );
                        const pat = /verifying|processing|please wait|checking your browser|slide to|swipe to|press (?:and|&) hold|hold to/i;
                        for (const b of els) {
                            const text = (b.textContent || b.value || '').trim();
                            if (text.length > 100) continue;
                            if (pat.test(text)) return true;
                        }
                        return false;
                    }
                """)
                if not still_present:
                    logger.info("PoW indicators cleared — gate passed")
                    pow_passed = True
                    break

            if pow_passed:
                with contextlib.suppress(TimeoutError, Exception):
                    await asyncio.wait_for(
                        page.wait_for_load_state("networkidle"),
                        timeout=10,
                    )
                await asyncio.sleep(random.uniform(1.5, 3.0))
            else:
                logger.warning(
                    "PoW/gate did not resolve within timeout — "
                    "capturing current state",
                )

    except Exception as e:
        logger.warning("Error waiting for gate resolution: %s", e)


async def _wait_for_form_submit(
    page, pre_click_url: str, timeout_remaining: float,
) -> None:
    """Wait for a checkbox gate's auto-submit form to fire and navigate."""
    form_timeout = min(15.0, max(5.0, timeout_remaining - 10.0))
    logger.info(
        "Waiting up to %.0fs for checkbox gate form submission", form_timeout,
    )

    try:
        await asyncio.sleep(4.0)

        if page.url != pre_click_url:
            logger.info("Form POST navigated to %s", page.url)
            with contextlib.suppress(TimeoutError, Exception):
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return

        with contextlib.suppress(TimeoutError, Exception):
            await asyncio.wait_for(
                page.wait_for_load_state("networkidle"),
                timeout=form_timeout,
            )

        await asyncio.sleep(random.uniform(2.0, 4.0))

        logger.info(
            "Checkbox gate form submitted, final URL: %s", page.url,
        )

    except Exception as e:
        logger.warning("Error during form submit wait: %s", e)


def browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
    turnstile_timeout: int = 30,
) -> tuple[Path | None, str, str | None, bool]:
    """Download a URL using a stealth browser (Camoufox).

    Synchronous wrapper around the async implementation for use in
    Celery tasks.  Returns ``(filepath, reason, final_url,
    interaction_driven)`` — final URL is the browser's location after
    all redirects/gates; interaction_driven is True when a CTA/gate
    was engaged to reach it (so it is not relay rotation).

    In addition to page.html, saves:
    - ``_browser_resources/`` — captured JS, PHP, CSS, XHR responses
    - ``_screenshots/`` — screenshots at each page stage
    - ``requests.json`` — full network request/response log
    """
    if not _is_available():
        return None, "camoufox not installed (pip install darla[browser])", None, False

    # Hard wall-clock deadline: timeout + turnstile_timeout + 60s buffer.
    # Buffer accounts for CTA click-through (detection + click + post-click
    # navigation/loading) on top of Turnstile resolution and page load.
    hard_timeout = timeout + turnstile_timeout + 60

    start = time.monotonic()
    try:
        loop = asyncio.new_event_loop()
        coro = _async_browser_download(url, dest_dir, timeout, turnstile_timeout)
        result = loop.run_until_complete(
            asyncio.wait_for(coro, timeout=hard_timeout)
        )
        elapsed = time.monotonic() - start
        logger.info("Browser download completed in %.1fs", elapsed)
        return result
    except TimeoutError:
        elapsed = time.monotonic() - start
        logger.error(
            "Browser download hard timeout after %.1fs (limit %ds)",
            elapsed, hard_timeout,
        )
        return None, f"Browser hard timeout after {hard_timeout}s", None, False
    except Exception as e:
        elapsed = time.monotonic() - start
        logger.error("Browser download wrapper failed after %.1fs: %s", elapsed, e)
        return None, f"Browser error: {type(e).__name__}: {e}", None, False
    finally:
        loop.close()
