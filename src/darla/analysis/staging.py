"""Attack-flow segmentation — split one render into ordered stages.

A browser render walks the victim through several pages (lure → bot check
→ interstitial → AiTM proxy).  The render worker records each top-level
navigation with a ``doc_seq`` counter and writes a ``stages.json``
manifest alongside ``page.html`` / ``requests.json``.  This module turns
that manifest — plus the network log and resource manifest already on
disk — into structured :class:`StageSpec` objects: one per page, with a
classified role, the navigation method that reached it, its saved body
and screenshot, and the sub-resources it loaded (attributed by
``doc_seq``).

The heavy lifting (role classification, resource attribution) is pure —
dicts in, dataclasses out — so it is fully unit-testable without a
browser.  :func:`segment_render` is the thin file-IO wrapper the render
finaliser calls.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from darla.models.stage import StageRole

logger = logging.getLogger(__name__)

# Hosts that phishing cloaks/burned-token redirects send analysts to.
# Landing on one of these after a gate means the token was spent or the
# ASN looked hostile — the stage is a decoy, not the real phish.
_DECOY_HOST_MARKERS = (
    "temu.com", "dhgate.com", "aliexpress.", "mvideo.ru", "office.com",
    "microsoft.com", "google.com", "bing.com", "duckduckgo.com",
    "wikipedia.org", "example.com",
)

# Visible-text markers per role (lowercased substring match).
_BOT_MARKERS = (
    "verify you are human", "verifying you are human", "checking your browser",
    "just a moment", "cloudflare", "ddos protection", "i'm not a robot",
    "press and hold", "review the security", "ray id",
)
_INTERSTITIAL_MARKERS = (
    "preparing", "please wait", "redirecting", "loading", "one moment",
    "securely connecting", "establishing", "processing your request",
)
_EMAIL_GATE_MARKERS = (
    "enter the email", "email address this", "confirm your email",
    "email that received", "verify your email to",
)
_POST_SUBMIT_MARKERS = (
    "thank you", "successfully", "you will be redirected", "sign-in successful",
    "verification complete",
)


@dataclass
class StageSpec:
    seq: int
    url: str | None
    host: str | None
    role: StageRole
    nav_method: str | None
    body_path: str | None            # relative to the render dir
    screenshot_path: str | None      # relative to the render dir
    status_code: int | None
    content_type: str | None
    dwell_seconds: float | None
    markers: dict = field(default_factory=dict)
    # Resources attributed to this doc_seq: list of
    # {url, initiator, doc_seq, ts, path} dicts.
    resources: list[dict] = field(default_factory=list)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def _is_decoy_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower()
    return any(m in h for m in _DECOY_HOST_MARKERS)


def classify_role(
    *,
    seq: int,
    total: int,
    url: str | None,
    visible_text: str,
    markers: dict,
    dwell_seconds: float | None,
    is_final: bool,
) -> StageRole:
    """Infer a stage's role from render-time signals.

    Signals, in priority order: explicit gate detections (Turnstile /
    custom bot gate / email-gate fill), password + IdP markers, decoy
    host, visible-text markers, and finally position/dwell heuristics.
    Returns :attr:`StageRole.UNKNOWN` rather than guessing when nothing
    fires — an honest blank the operator can correct.
    """
    text = (visible_text or "").lower()
    host = _host(url)

    # 1. Explicit render-time detections (most reliable).
    if markers.get("turnstile") or markers.get("bot_gate"):
        return StageRole.BOT_CHECK
    if markers.get("email_gate_filled") or markers.get("email_gate_present"):
        return StageRole.EMAIL_GATE

    # 2. Credential capture — a password field, or an IdP the page wraps.
    #    A benign IdP host with a password field is still the real login
    #    being proxied — treat as cred capture unless it's an obvious decoy.
    if (markers.get("password_field") or markers.get("idp")) and not _is_decoy_host(host):
        return StageRole.CRED_CAPTURE

    # 3. Decoy — landed on a known cloak destination.
    if _is_decoy_host(host):
        return StageRole.DECOY

    # 4. Visible-text markers.
    if any(m in text for m in _BOT_MARKERS):
        return StageRole.BOT_CHECK
    if any(m in text for m in _EMAIL_GATE_MARKERS):
        return StageRole.EMAIL_GATE
    if any(m in text for m in _POST_SUBMIT_MARKERS) and (is_final or seq > 0):
        return StageRole.POST_SUBMIT
    if any(m in text for m in _INTERSTITIAL_MARKERS):
        return StageRole.INTERSTITIAL

    # 5. Position / dwell heuristics (weakest).
    if seq == 0 and total > 1:
        return StageRole.LURE
    # A short-dwell middle hop with little text is a pure redirector.
    if (
        not is_final
        and (dwell_seconds is not None and dwell_seconds < 1.5)
        and len(text.strip()) < 40
    ):
        return StageRole.REDIRECTOR
    if is_final:
        # Final page with a form-ish structure but no password detected:
        # still most likely the capture page.
        if markers.get("has_form"):
            return StageRole.CRED_CAPTURE
        return StageRole.UNKNOWN
    return StageRole.UNKNOWN


def attribute_resources(
    network_log: list[dict],
    resource_manifest: list[dict],
    doc_seq_bounds: list[tuple[float, float]],
) -> dict[int, list[dict]]:
    """Attribute captured resources to the document (stage) that loaded them.

    Each entry in ``resource_manifest`` carries a ``timestamp`` (seconds
    since nav start) and ``url``.  ``doc_seq_bounds`` gives, per stage seq,
    the ``(start_ts, end_ts)`` window.  A resource is attributed to the
    stage whose window contains its timestamp; resources before the first
    or after the last boundary clamp to the nearest stage.  Falls back to
    a network-log ``doc_seq`` field when the capture stamped one directly.
    """
    by_url_seq: dict[str, int] = {}
    for e in network_log if isinstance(network_log, list) else []:
        if isinstance(e, dict) and e.get("doc_seq") is not None and e.get("url"):
            by_url_seq.setdefault(e["url"], e["doc_seq"])

    def _seq_for(ts: float | None, url: str | None) -> int:
        if url and url in by_url_seq:
            return by_url_seq[url]
        if ts is None or not doc_seq_bounds:
            return 0
        for seq, (lo, hi) in enumerate(doc_seq_bounds):
            if lo <= ts < hi:
                return seq
        return len(doc_seq_bounds) - 1

    out: dict[int, list[dict]] = {}
    for r in resource_manifest if isinstance(resource_manifest, list) else []:
        if not isinstance(r, dict):
            continue
        role = r.get("role")
        if role in ("final", "initial"):
            # These are stage bodies, not sub-resources.
            continue
        ts = r.get("timestamp")
        seq = _seq_for(ts, r.get("url"))
        out.setdefault(seq, []).append({
            "url": r.get("url"),
            "initiator": _initiator_for(r),
            "doc_seq": seq,
            "ts": ts,
            "path": r.get("filename"),
            "content_type": r.get("content_type"),
            "status": r.get("status"),
        })
    return out


def _initiator_for(manifest_entry: dict) -> str:
    ct = (manifest_entry.get("content_type") or "").lower()
    method = (manifest_entry.get("method") or "GET").upper()
    if "javascript" in ct or (manifest_entry.get("filename") or "").endswith(".js"):
        return "script_src"
    if "css" in ct:
        return "css"
    if method != "GET":
        return "xhr"
    if "json" in ct:
        return "fetch"
    if "html" in ct:
        return "iframe"
    return "other"


def build_stage_specs(
    stages_manifest: list[dict],
    network_log: list[dict],
    resource_manifest: list[dict],
) -> list[StageSpec]:
    """Pure core: assemble ordered :class:`StageSpec` from parsed inputs.

    ``stages_manifest`` is the list under ``stages.json``'s ``"stages"``
    key.  Each item has ``seq, url, nav_method, body_file,
    screenshot_file, status_code, content_type, started_ts, ended_ts,
    visible_text, markers``.  Missing fields degrade gracefully.
    """
    stages_manifest = sorted(
        (s for s in stages_manifest if isinstance(s, dict)),
        key=lambda s: s.get("seq", 0),
    )
    total = len(stages_manifest)

    bounds: list[tuple[float, float]] = []
    for s in stages_manifest:
        lo = float(s.get("started_ts") or 0.0)
        hi = s.get("ended_ts")
        hi = float(hi) if hi is not None else float("inf")
        bounds.append((lo, hi))

    res_by_seq = attribute_resources(network_log, resource_manifest, bounds)

    specs: list[StageSpec] = []
    for idx, s in enumerate(stages_manifest):
        seq = s.get("seq", idx)
        url = s.get("url")
        markers = s.get("markers") if isinstance(s.get("markers"), dict) else {}
        started = s.get("started_ts")
        ended = s.get("ended_ts")
        dwell = s.get("dwell_seconds")
        if dwell is None and started is not None and ended is not None:
            dwell = round(float(ended) - float(started), 3)
        is_final = idx == total - 1
        role = classify_role(
            seq=seq,
            total=total,
            url=url,
            visible_text=s.get("visible_text") or "",
            markers=markers,
            dwell_seconds=dwell,
            is_final=is_final,
        )
        specs.append(StageSpec(
            seq=seq,
            url=url,
            host=_host(url),
            role=role,
            nav_method=s.get("nav_method"),
            body_path=s.get("body_file"),
            screenshot_path=s.get("screenshot_file"),
            status_code=s.get("status_code"),
            content_type=s.get("content_type"),
            dwell_seconds=dwell,
            markers=markers,
            resources=res_by_seq.get(seq, []),
        ))
    return specs


def _load_json(path: Path, default):
    try:
        if not path.is_file() or path.stat().st_size > 32_000_000:
            return default
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return default


def segment_render(dest_dir: str | Path) -> list[StageSpec]:
    """File-IO wrapper: read a render dir's manifests and segment it.

    Returns ``[]`` when no ``stages.json`` is present (older renders, or a
    non-render kit) — the caller then falls back to a single synthetic
    stage from ``page.html``.
    """
    dest = Path(dest_dir)
    stages_doc = _load_json(dest / "stages.json", {})
    stages_manifest = stages_doc.get("stages") if isinstance(stages_doc, dict) else None
    if not stages_manifest:
        return []
    network_log = _load_json(dest / "requests.json", [])
    manifest = _load_json(dest / "_browser_resources" / "_manifest.json", [])
    return build_stage_specs(stages_manifest, network_log, manifest)
