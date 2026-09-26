"""Ancestor-dedup tests for browser_download_kit.

Exercises the pure-logic helper ``_find_ancestor_match`` so we can cover
the Cloudflare-Turnstile convergence case (per-session nonces break
byte-level TLSH matching even though the kit is looping on the same
gate) without spinning up Camoufox, Postgres, or Celery.

The specific scenario: a victim chain hits a Cloudflare Turnstile
challenge at depth 3.  Each subsequent browser_render child lands on
the EXACT SAME CF challenge URL, but Turnstile injects fresh nonces
per render so TLSH distance between the renders ranges 36–83 — well
above the default threshold of 30.  Without a URL-equivalence check,
the ancestor-chain dedup misses, the kit isn't marked stuck_at_gate,
the post-download analysis chain keeps firing, and depth escalates
3 → 4 → 5 indefinitely.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from darla.tasks.browser import _find_ancestor_match

# ---------------------------------------------------------------------------
# Minimal Kit stand-in — only the attributes _find_ancestor_match reads.
# Using a dataclass avoids SQLAlchemy session machinery in this unit test.
# ---------------------------------------------------------------------------

@dataclass
class _KitStub:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    source_url: str | None = None
    discovery_method: str | None = None
    chain_depth: int = 0
    tlsh: str | None = None
    sha256: str | None = None


# Real-world TLSH hashes pulled from investigation
# 0f0f239a-19d8-47ae-a87d-c7676911aeca — three consecutive Cloudflare
# Turnstile renders of the same challenge URL.  Distances between
# adjacent pairs are 36–83; none fall under the default threshold of 30.
_CF_TURNSTILE_URL = (
    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/"
    "turnstile/f/ov2/av0/rch/7v7jl/0x4AAAAAAC999SE6RBmW0zj5/auto/fbE/"
    "new/normal?lang=auto"
)
_TLSH_DEPTH_3 = (
    "T120343C8B7DDEB51AA3A36434403770DEF76A2CC8300D5A0BE2115AF47C9536D6AB2D9C"
)
_TLSH_DEPTH_4 = (
    "T180341A8B79DFB51963636079402B34DBF36E3C94700C6A0AE21096F07DA535D6EB2DAC"
)
_TLSH_DEPTH_5 = (
    "T176340ACF7DDFB12A63776475402B34EAA36B6C84601D690AF21099F07DE431A6EB2C5C"
)

_DEFAULT_THRESHOLD = 30


# ---------------------------------------------------------------------------
# URL-equality signal — the Turnstile convergence case.
# ---------------------------------------------------------------------------

def test_url_equality_catches_turnstile_rerender_above_tlsh_threshold() -> None:
    """Same rendered URL + TLSH distance > threshold → still stuck.

    This is the exact pattern that caused the depth-3/4/5 CF-challenge
    re-render loop in investigation 0f0f239a-19d8-47ae-a87d-c7676911aeca.
    Without the URL-equivalence check, TLSH distance 59 clears the
    threshold of 30 and the kit gets promoted instead of suppressed.
    """
    ancestor = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_3,
    )
    child = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=4,
        tlsh=_TLSH_DEPTH_4,
    )
    matched, reason = _find_ancestor_match(
        child, [ancestor], _DEFAULT_THRESHOLD,
    )
    assert matched is ancestor
    assert "Same rendered URL" in reason
    assert str(ancestor.id) in reason


def test_three_consecutive_turnstile_renders_all_flagged() -> None:
    """Depth 3, 4, 5 all render the same CF URL → each should be caught.

    Simulates walking up the ancestor chain at each successive re-render
    and asserts dedup fires every time — i.e. no new browser_render
    child would be dispatched for depths 4 or 5.
    """
    depth3 = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_3,
    )
    # Depth-4 child lands on the same URL — should match depth-3 ancestor.
    depth4 = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=4,
        tlsh=_TLSH_DEPTH_4,
    )
    matched, _ = _find_ancestor_match(depth4, [depth3], _DEFAULT_THRESHOLD)
    assert matched is depth3

    # Depth-5 child — ancestors walk order is parent-first, so depth-4
    # is checked first and matches.
    depth5 = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=5,
        tlsh=_TLSH_DEPTH_5,
    )
    matched, _ = _find_ancestor_match(
        depth5, [depth4, depth3], _DEFAULT_THRESHOLD,
    )
    assert matched is depth4


# ---------------------------------------------------------------------------
# Boundary cases — the URL check must NOT over-suppress.
# ---------------------------------------------------------------------------

def test_first_browser_render_of_httpx_parent_not_suppressed() -> None:
    """The first browser render's source_url equals its httpx parent's
    URL (on a no-redirect render), but the parent's discovery_method is
    NOT 'browser_render'.  The URL check must be skipped so the first
    render can proceed normally."""
    httpx_parent = _KitStub(
        source_url="https://lure.example.com/loader.js",
        discovery_method="feed_url",  # or whatever non-browser method
        chain_depth=0,
        tlsh="T1" + "0" * 68,  # synthetic, far from child's tlsh
    )
    first_render = _KitStub(
        source_url="https://lure.example.com/loader.js",
        discovery_method="browser_render",
        chain_depth=1,
        tlsh="T1" + "F" * 68,  # synthetic, far TLSH
    )
    matched, reason = _find_ancestor_match(
        first_render, [httpx_parent], _DEFAULT_THRESHOLD,
    )
    assert matched is None
    assert reason == ""


def test_different_urls_no_url_match_and_tlsh_above_threshold() -> None:
    """Different rendered URLs + distant TLSH → not stuck.

    Sibling relay domains legitimately produce different final URLs
    with similar-but-not-identical content.  When TLSH distance is
    above threshold AND URLs differ, this is real discovery, not a
    loop.
    """
    ancestor = _KitStub(
        source_url="https://relay-1.example.com/a",
        discovery_method="browser_render",
        chain_depth=2,
        tlsh=_TLSH_DEPTH_3,
    )
    child = _KitStub(
        source_url="https://relay-2.example.com/b",
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_5,  # distance 83 from ancestor
    )
    matched, _ = _find_ancestor_match(child, [ancestor], _DEFAULT_THRESHOLD)
    assert matched is None


def test_url_match_requires_browser_render_ancestor() -> None:
    """An httpx-fetched ancestor with the same source_url does NOT
    trigger suppression — URL-equality is only meaningful against
    prior browser renders of that URL."""
    httpx_ancestor = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="chain_crawler",  # not a browser render
        chain_depth=2,
        tlsh="T1" + "0" * 68,
    )
    child = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_3,
    )
    matched, _ = _find_ancestor_match(
        child, [httpx_ancestor], _DEFAULT_THRESHOLD,
    )
    assert matched is None


def test_missing_source_url_falls_through_to_content_check() -> None:
    """A kit without source_url must not crash and must still get
    content-matched against its ancestors."""
    ancestor = _KitStub(
        source_url=None,
        discovery_method="browser_render",
        chain_depth=2,
        tlsh=_TLSH_DEPTH_3,
    )
    # Same TLSH → content-match fires even though URL is None.
    child = _KitStub(
        source_url=None,
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_3,
    )
    matched, reason = _find_ancestor_match(
        child, [ancestor], _DEFAULT_THRESHOLD,
    )
    assert matched is ancestor
    assert "Content matches" in reason


# ---------------------------------------------------------------------------
# Preserved behavior: content-match still fires when it should.
# ---------------------------------------------------------------------------

def test_content_match_still_fires_on_low_tlsh_distance() -> None:
    """If URLs differ but content is nearly identical (TLSH distance
    below threshold), we still treat it as stuck — preserves the
    pre-existing behavior for non-URL-driven loops."""
    # Identical TLSH → distance 0 → content match.
    ancestor = _KitStub(
        source_url="https://a.example.com/",
        discovery_method="browser_render",
        chain_depth=2,
        tlsh=_TLSH_DEPTH_3,
    )
    child = _KitStub(
        source_url="https://b.example.com/",
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=_TLSH_DEPTH_3,
    )
    matched, reason = _find_ancestor_match(
        child, [ancestor], _DEFAULT_THRESHOLD,
    )
    assert matched is ancestor
    assert "Content matches" in reason
    assert "TLSH distance 0" in reason


def test_exact_sha256_match_fires_when_tlsh_missing() -> None:
    """Tiny files have no TLSH (<50 bytes); SHA256 fallback catches
    exact duplicates."""
    shared_sha = "a" * 64
    ancestor = _KitStub(
        source_url="https://a.example.com/",
        discovery_method="browser_render",
        chain_depth=2,
        tlsh=None,
        sha256=shared_sha,
    )
    child = _KitStub(
        source_url="https://b.example.com/",
        discovery_method="browser_render",
        chain_depth=3,
        tlsh=None,
        sha256=shared_sha,
    )
    matched, reason = _find_ancestor_match(
        child, [ancestor], _DEFAULT_THRESHOLD,
    )
    assert matched is ancestor
    assert "SHA256" in reason


def test_empty_ancestor_chain_returns_no_match() -> None:
    """Root kits have no ancestors — no match, no crash."""
    child = _KitStub(
        source_url=_CF_TURNSTILE_URL,
        discovery_method="browser_render",
        chain_depth=0,
        tlsh=_TLSH_DEPTH_3,
    )
    matched, reason = _find_ancestor_match(child, [], _DEFAULT_THRESHOLD)
    assert matched is None
    assert reason == ""
