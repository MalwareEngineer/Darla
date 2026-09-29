"""Render navigation-path surfacing, settle timing, and relay-vs-interaction.

Reviewing one investigation (an email-gate lure): the render
was stored as one node under the click-tracker with only its final URL, so
the lure→gate→credential steps were invisible; the credential screenshot
caught a loading spinner; and reaching the credential domain via the gate
fill looked like relay rotation, costing a duplicate render.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from types import SimpleNamespace

import pytest

from darla.analysis import browser_downloader
from darla.analysis.browser_downloader import _LOADING_MARKERS, _settle_final_page
from darla.api.investigations import _render_nav_path
from darla.tasks import browser as browser_module

# ---------------------------------------------------------------------------
# nav_path from the persisted network log
# ---------------------------------------------------------------------------

def _write_log(dir_, entries) -> str:
    (dir_ / "requests.json").write_text(json.dumps(entries), encoding="utf-8")
    return str(dir_ / "page.html")


def _doc(url: str) -> dict:
    return {"type": "request", "resource_type": "document", "url": url}


def test_nav_path_lists_distinct_document_hosts_in_order(tmp_path) -> None:
    local = _write_log(tmp_path, [
        _doc("https://tracker.test/track?e=abc"),
        {"type": "request", "resource_type": "image", "url": "https://cdn.test/x.png"},
        _doc("https://lure.test/agreement"),
        _doc("https://lure.test/agreement/step2"),  # same host, collapsed
        _doc("https://creds.test/r/token"),
    ])
    kit = SimpleNamespace(discovery_method="browser_render", local_path=local)
    assert _render_nav_path(kit) == [
        "tracker.test", "lure.test", "creds.test",
    ]


def test_nav_path_skips_iframe_documents(tmp_path) -> None:
    """An AiTM login page's session-probe iframe (Me.htm on another
    subdomain) is a "document" request but not a hop the browser took —
    it must not show up as the chain's final host."""
    local = _write_log(tmp_path, [
        _doc("https://lure.test/"),
        _doc("https://login.aitm.test/authorize"),
        {
            "type": "request", "resource_type": "document",
            "url": "https://probe.aitm.test/Me.htm?v=3",
            "headers": {"Sec-Fetch-Dest": "iframe"},
        },
    ])
    kit = SimpleNamespace(discovery_method="browser_render", local_path=local)
    assert _render_nav_path(kit) == ["lure.test", "login.aitm.test"]


def test_nav_path_none_for_non_render_kits(tmp_path) -> None:
    local = _write_log(tmp_path, [_doc("https://a.test/"), _doc("https://b.test/")])
    kit = SimpleNamespace(discovery_method="redirect", local_path=local)
    assert _render_nav_path(kit) is None


def test_nav_path_none_for_single_hop(tmp_path) -> None:
    local = _write_log(tmp_path, [_doc("https://only.test/")])
    kit = SimpleNamespace(discovery_method="browser_render", local_path=local)
    assert _render_nav_path(kit) is None


def test_nav_path_tolerates_missing_or_bad_log(tmp_path) -> None:
    missing = SimpleNamespace(
        discovery_method="browser_render", local_path=str(tmp_path / "page.html"),
    )
    assert _render_nav_path(missing) is None
    (tmp_path / "requests.json").write_text("{not json", encoding="utf-8")
    assert _render_nav_path(missing) is None


def test_nav_path_none_without_local_path() -> None:
    kit = SimpleNamespace(discovery_method="browser_render", local_path=None)
    assert _render_nav_path(kit) is None


def test_build_tree_offloads_the_blocking_read() -> None:
    """The tree endpoint is async; the per-render disk read + JSON parse
    must run off the event loop, not inline."""
    from darla.api.investigations import _build_tree

    assert inspect.iscoroutinefunction(_build_tree)
    src = inspect.getsource(_build_tree)
    assert "asyncio.to_thread(_render_nav_path" in src


# ---------------------------------------------------------------------------
# _settle_final_page — content-agnostic stability
# ---------------------------------------------------------------------------

class _FakePage:
    """Scripted (url, html, visible_text) frames.

    ``content()`` serves the next frame's HTML (and advances); ``inner_text``
    returns the *current* frame's visible text without advancing, mirroring
    how _settle_final_page reads content then visible text each iteration.
    """

    def __init__(self, frames: list[tuple[str, str, str]]):
        self._frames = frames
        self._i = 0
        self._cur = frames[0]
        self.url = frames[0][0]

    async def content(self) -> str:
        self._cur = self._frames[min(self._i, len(self._frames) - 1)]
        self._i += 1
        self.url = self._cur[0]
        return self._cur[1]

    async def inner_text(self, _selector: str) -> str:
        return self._cur[2]

    async def wait_for_load_state(self, *_a, **_k):
        return None


@pytest.fixture(autouse=True)
def _instant_sleep(monkeypatch):
    async def _no_sleep(*_a, **_k):
        return None

    monkeypatch.setattr(browser_downloader.asyncio, "sleep", _no_sleep)


# Fixed-length bodies so content-length never changes — isolating the
# visible-text/URL signals under test from the length-stability signal.
_BODY_A = "<html><body>" + "x" * 600 + "</body></html>"
_BODY_B = "<html><body>" + "y" * 600 + "</body></html>"
_CLEAN = "email password sign in"


async def test_settle_waits_out_a_visible_spinner() -> None:
    marker = _LOADING_MARKERS[0]
    url = "https://creds.test/r"
    page = _FakePage([
        (url, _BODY_A, marker),   # visible spinner — keeps waiting
        (url, _BODY_A, marker),
        (url, _BODY_B, _CLEAN),   # same length, markerless — now settling
        (url, _BODY_B, _CLEAN),
        (url, _BODY_B, _CLEAN),
    ])
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    # Waited past the two spinner frames (only the marker held it there,
    # since URL and content-length were stable throughout).
    assert page._i >= 3


async def test_loading_class_in_html_does_not_delay_a_clean_page() -> None:
    """Regression: a hidden loading-overlay / lazy-loading class in the
    HTML source must not force the full max_seconds wait when the visible
    text shows no spinner."""
    html = (
        "<html><head><style>.loading-overlay{display:none}</style></head>"
        "<body><img class='lazy-loading'>" + "x" * 400 + "</body></html>"
    )
    page = _FakePage([("https://creds.test/", html, _CLEAN)] * 6)
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    assert page._i <= 3  # settled promptly despite "loading" in the HTML


async def test_settle_waits_through_a_navigation() -> None:
    page = _FakePage([
        ("https://lure.test/gate", _BODY_A, _CLEAN),
        ("https://creds.test/login", _BODY_B, _CLEAN),  # url changed
        ("https://creds.test/login", _BODY_B, _CLEAN),
        ("https://creds.test/login", _BODY_B, _CLEAN),
    ])
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    assert page.url == "https://creds.test/login"
    assert page._i >= 3


async def test_settle_returns_promptly_on_stable_page() -> None:
    page = _FakePage([("https://creds.test/", _BODY_A, _CLEAN)] * 6)
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    # Seeded from current state, so two stable checks settle it.
    assert page._i <= 3


async def test_settle_is_bounded_when_spinner_never_clears() -> None:
    marker = _LOADING_MARKERS[0]
    page = _FakePage([("https://x.test/", _BODY_A, marker)] * 100)
    # max_seconds/interval caps iterations even though it never settles.
    await asyncio.wait_for(
        _settle_final_page(page, interval=0.0, max_seconds=0.0), timeout=5,
    )


# ---------------------------------------------------------------------------
# Interaction-driven landing is not relay rotation
# ---------------------------------------------------------------------------

def test_browser_download_returns_interaction_flag() -> None:
    """Success return is a 4-tuple carrying cta_clicked."""
    src = inspect.getsource(browser_downloader._async_browser_download)
    assert 'return filepath, "ok", final_url, cta_clicked' in src


def test_rotation_suppressed_when_interaction_driven() -> None:
    src = inspect.getsource(browser_module.browser_download_kit)
    assert "interaction_driven" in src
    assert "and not interaction_driven" in src
    # The caller unpacks the 4th value.
    assert "final_url, interaction_driven = browser_download(" in src


def test_all_browser_download_returns_are_four_tuples() -> None:
    for fn in (browser_downloader._async_browser_download, browser_downloader.browser_download):
        src = inspect.getsource(fn)
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("return ") and "None," in stripped:
                # every early/error return carries the interaction flag
                assert stripped.endswith(", False"), stripped
