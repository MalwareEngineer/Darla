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


# ---------------------------------------------------------------------------
# _settle_final_page — content-agnostic stability
# ---------------------------------------------------------------------------

class _FakePage:
    """Yields a scripted sequence of (url, content) on each .content() call."""

    def __init__(self, frames: list[tuple[str, str]]):
        self._frames = frames
        self._i = 0
        self.url = frames[0][0]

    async def content(self) -> str:
        url, html = self._frames[min(self._i, len(self._frames) - 1)]
        self.url = url
        self._i += 1
        return html

    async def wait_for_load_state(self, *_a, **_k):
        return None


@pytest.fixture(autouse=True)
def _instant_sleep(monkeypatch):
    async def _no_sleep(*_a, **_k):
        return None

    monkeypatch.setattr(browser_downloader.asyncio, "sleep", _no_sleep)


async def test_settle_waits_out_a_loading_spinner() -> None:
    marker = _LOADING_MARKERS[0]
    stable = "<html><body>credential form here" + "x" * 500 + "</body></html>"
    page = _FakePage([
        ("https://creds.test/r", f"<html><body>{marker}</body></html>"),
        ("https://creds.test/r", f"<html><body>{marker}</body></html>"),
        ("https://creds.test/r", stable),
        ("https://creds.test/r", stable),
        ("https://creds.test/r", stable),
    ])
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    # It kept polling past the spinner frames to reach the stable content.
    assert page._i >= 4


async def test_settle_waits_through_a_navigation() -> None:
    a = "<html><body>gate page" + "x" * 400 + "</body></html>"
    b = "<html><body>credential page" + "y" * 400 + "</body></html>"
    page = _FakePage([
        ("https://lure.test/gate", a),
        ("https://creds.test/login", b),  # url changed → not settled yet
        ("https://creds.test/login", b),
        ("https://creds.test/login", b),
    ])
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    assert page.url == "https://creds.test/login"
    assert page._i >= 3


async def test_settle_returns_promptly_on_stable_page() -> None:
    html = "<html><body>done" + "z" * 400 + "</body></html>"
    page = _FakePage([("https://creds.test/", html)] * 6)
    await _settle_final_page(page, interval=0.0, max_seconds=100.0)
    # Two stable checks are enough; it does not exhaust all frames.
    assert page._i <= 3


async def test_settle_is_bounded_when_spinner_never_clears() -> None:
    marker = _LOADING_MARKERS[0]
    spin = f"<html><body>{marker}</body></html>"
    page = _FakePage([("https://x.test/", spin)] * 100)
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
