"""Stage fingerprinting — role-scoped similarity primitives.

A whole-file TLSH tells you two *pages* are similar; it does not tell you
that two *bot checks* are the same library behind different lures, nor
that two AiTM proxies wrap the same real Microsoft login while injecting
different harvesters.  This module computes the several complementary
signals a stage needs so comparison can be role-scoped and, for
credential pages, baseline-subtracted:

    tlsh_raw          TLSH of the raw server response (author's template,
                      before JS runs)
    tlsh_rendered     TLSH of the rendered DOM after normalize_html strips
                      per-victim tokens (result after JS runs)
    skeleton_hash     hash of the tag-path skeleton — same layout even
                      when class names / ids / text rotate
    script_shas       set of SHA-256s of the scripts the stage loaded
                      ("loads the same bot-check library")
    request_shape     normalised method+path-template sequence + ws — the
                      backend protocol fingerprint
    screenshot_phash  perceptual hash (dhash) of the screenshot

Everything here is pure and dependency-light: TLSH and Pillow are
optional and degrade to ``None`` when unavailable, exactly like
:mod:`darla.analysis.hasher`.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from darla.analysis.polymorphism import _parse_html, normalize_html

# ---------------------------------------------------------------------------
# TLSH helpers
# ---------------------------------------------------------------------------


def tlsh_of_text(text: str) -> str | None:
    """TLSH hash of ``text`` (UTF-8), or None when unavailable/too small."""
    if not text:
        return None
    try:
        import tlsh

        h = tlsh.hash(text.encode("utf-8", errors="replace"))
        return None if h in ("", "TNULL") else h
    except Exception:
        return None


def tlsh_distance(a: str | None, b: str | None) -> int | None:
    """TLSH distance between two hashes, or None if either is missing."""
    if not a or not b:
        return None
    try:
        import tlsh

        return tlsh.diff(a, b)
    except Exception:
        return None


def tlsh_bucket(h: str | None, nibbles: int = 4) -> str | None:
    """Coarse bucket for candidate pre-filtering.

    TLSH's first byte is a header (checksum + length quantile); the body
    digest starts after it.  We bucket on the leading body nibbles so
    stages that are plausibly close share a bucket without a full O(n)
    distance scan.  This is a recall-oriented filter, not a guarantee —
    always confirm with :func:`tlsh_distance`.
    """
    if not h or len(h) < 6 + nibbles:
        return None
    return h[6 : 6 + nibbles].lower()


# ---------------------------------------------------------------------------
# Tag skeleton
# ---------------------------------------------------------------------------


def tag_skeleton(html: str) -> list[str]:
    """Ordered list of tag-path strings (``html>body>div>form``).

    Ignores attributes and text entirely, so class-name/id/text
    randomisation between per-victim renders does not change it.
    """
    return [el.tag_path for el in _parse_html(html or "")]


def skeleton_hash(html: str) -> str | None:
    """Stable hash of the tag skeleton, or None for empty/unparseable input."""
    skel = tag_skeleton(html)
    if not skel:
        return None
    joined = "\n".join(skel)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


def skeleton_similarity(a: list[str], b: list[str]) -> float:
    """Jaccard similarity of two tag skeletons (multiset-insensitive)."""
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# ---------------------------------------------------------------------------
# Rendered / raw content hashes
# ---------------------------------------------------------------------------


def rendered_tlsh(html: str) -> str | None:
    """TLSH over the normalised (deobfuscated, token-stripped) DOM."""
    if not html:
        return None
    return tlsh_of_text(normalize_html(html))


# ---------------------------------------------------------------------------
# Script set
# ---------------------------------------------------------------------------


def jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard index of two sets; 1.0 when both empty."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Request-sequence shape
# ---------------------------------------------------------------------------

# Path segments that are really per-victim/per-session tokens, normalised
# to ``{t}`` so the *shape* of the request sequence survives rotation.
# Hex token: 8+ hex chars, OR 4+ hex chars that mix a letter and a digit
# (``9f3b`` is a session token; ``auth`` / ``cafe`` are words we keep).
_HEX_SEG = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
_HEX_MIXED_SEG = re.compile(
    r"^(?=[0-9a-f]{4,}$)(?=.*[0-9])(?=.*[a-f]).*$", re.IGNORECASE
)
_UUID_SEG = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NUM_SEG = re.compile(r"^\d+$")
_B64_SEG = re.compile(r"^[A-Za-z0-9_\-]{16,}={0,2}$")


def _normalize_segment(seg: str) -> str:
    if not seg:
        return seg
    if (
        _UUID_SEG.match(seg)
        or _HEX_SEG.match(seg)
        or _HEX_MIXED_SEG.match(seg)
        or _NUM_SEG.match(seg)
    ):
        return "{t}"
    if _B64_SEG.match(seg):
        return "{t}"
    return seg.lower()


def path_template(url: str) -> str:
    """``https://a.com/api/9f3b/login?x=1`` → ``a.com/api/{t}/login``.

    Host kept (backend infra is part of the protocol shape); tokenised
    path segments collapsed to ``{t}``; query dropped (values rotate,
    keys are noisy).  Used both for request-shape hashing and display.
    """
    try:
        p = urlparse(url)
    except Exception:
        return url
    host = (p.hostname or "").lower()
    segs = [s for s in (p.path or "").split("/") if s]
    norm = "/".join(_normalize_segment(s) for s in segs)
    return f"{host}/{norm}" if norm else host


def request_shape(network_log: list[dict]) -> list[str]:
    """Ordered ``METHOD host/path/template`` tokens for main resources.

    Consumes the render's ``requests.json`` entries.  Keeps *request*
    rows (methods carry protocol meaning); folds a WebSocket open into a
    ``WS host/path`` token.  Consecutive identical tokens collapse so a
    beacon polled 40× doesn't dominate.
    """
    tokens: list[str] = []
    for e in network_log if isinstance(network_log, list) else []:
        if not isinstance(e, dict):
            continue
        if e.get("type") != "request":
            continue
        method = (e.get("method") or "GET").upper()
        rtype = e.get("resource_type") or ""
        # xhr/fetch/document are the protocol-bearing requests; skip
        # image/font/media/stylesheet noise unless it's a document.
        if rtype in ("image", "font", "media", "stylesheet"):
            continue
        tok = f"{method} {path_template(e.get('url') or '')}"
        if not tokens or tokens[-1] != tok:
            tokens.append(tok)
    return tokens


def request_shape_hash(network_log: list[dict]) -> str | None:
    shape = request_shape(network_log)
    if not shape:
        return None
    return hashlib.sha256("\n".join(shape).encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Screenshot perceptual hash (dhash) — optional Pillow
# ---------------------------------------------------------------------------


def screenshot_phash(path: str) -> str | None:
    """64-bit difference hash of an image file, as 16 hex chars.

    Returns None when Pillow is missing or the file is unreadable, so the
    signal is simply absent rather than fatal.
    """
    try:
        from PIL import Image
    except Exception:
        return None
    try:
        with Image.open(path) as im:
            im = im.convert("L").resize((9, 8), Image.BILINEAR)
            px = list(im.getdata())
        bits = 0
        idx = 0
        for row in range(8):
            for col in range(8):
                left = px[row * 9 + col]
                right = px[row * 9 + col + 1]
                bits = (bits << 1) | (1 if left > right else 0)
                idx += 1
        return f"{bits:016x}"
    except Exception:
        return None


def phash_distance(a: str | None, b: str | None) -> int | None:
    """Hamming distance between two 64-bit hex dhashes (0 = identical)."""
    if not a or not b:
        return None
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# IdP baseline detection + subtraction (for AiTM cred pages)
# ---------------------------------------------------------------------------

# Markers that identify the real login page an AiTM proxy is wrapping.
# An AiTM cred page is ~90% the proxied IdP HTML; comparing it whole makes
# every Microsoft-login AiTM look identical.  We detect which IdP it wraps
# so the caller can subtract that baseline and fingerprint only what the
# kit *injected* (its own scripts, endpoints, rewritten URLs).
_IDP_MARKERS: dict[str, tuple[str, ...]] = {
    "microsoft": (
        "login.microsoftonline.com",
        "convergedLogin",
        "urlMsaSignUp",
        "aadcdn.msauth",
        '"sFT"',
        "lightbox-cover",
    ),
    "google": (
        "accounts.google.com",
        "gaia_loginform",
        "signin/v2/identifier",
        "GALX",
    ),
    "okta": ("okta-sign-in", "oktaData", "/api/v1/authn"),
    "adfs": ("/adfs/ls", "MSISAuth", "userNameInput"),
}


def detect_idp_baseline(html: str, url: str = "") -> str | None:
    """Return the IdP name an AiTM page is wrapping, or None.

    Cheap substring scan over the rendered HTML (and URL).  Two distinct
    markers must match to avoid a stray keyword misclassifying a page.
    """
    hay = f"{url}\n{html or ''}".lower()
    best: str | None = None
    best_hits = 0
    for name, markers in _IDP_MARKERS.items():
        hits = sum(1 for m in markers if m.lower() in hay)
        if hits >= 2 and hits > best_hits:
            best, best_hits = name, hits
    return best


def injected_fingerprint(
    stage_script_shas: set[str],
    baseline_script_shas: set[str],
    stage_endpoints: set[str],
    baseline_endpoints: set[str],
) -> dict:
    """Fingerprint only what the kit added on top of the IdP baseline.

    The interesting, kit-identifying content is the difference: scripts
    and endpoints present on the AiTM page but not on the genuine IdP
    login.  Returns the injected sets plus a stable hash of them.
    """
    inj_scripts = sorted(stage_script_shas - baseline_script_shas)
    inj_endpoints = sorted(stage_endpoints - baseline_endpoints)
    material = "\n".join(inj_scripts) + "\n--\n" + "\n".join(inj_endpoints)
    return {
        "injected_scripts": inj_scripts,
        "injected_endpoints": inj_endpoints,
        "injected_hash": hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
        if material.strip("-\n")
        else None,
    }


# ---------------------------------------------------------------------------
# Endpoint extraction (ws:// and exfil URLs) from a network log
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"wss?://[^\s'\"<>`]+", re.IGNORECASE)


def extract_endpoints(network_log: list[dict], extra_text: str = "") -> set[str]:
    """Distinct backend endpoints (as path templates) a stage talked to.

    Pulls xhr/fetch request URLs and WebSocket URLs from the network log,
    plus any ``wss://`` found in ``extra_text`` (e.g. inline script).
    Normalised via :func:`path_template` so per-session tokens collapse.
    """
    endpoints: set[str] = set()
    for e in network_log if isinstance(network_log, list) else []:
        if not isinstance(e, dict):
            continue
        rtype = e.get("resource_type") or ""
        etype = e.get("type")
        url = e.get("url") or ""
        if etype == "request" and rtype in ("xhr", "fetch", "websocket"):
            endpoints.add(path_template(url))
        if url.lower().startswith(("ws://", "wss://")):
            endpoints.add(path_template(url))
    for m in _WS_RE.finditer(extra_text or ""):
        endpoints.add(path_template(m.group(0)))
    endpoints.discard("")
    return endpoints
