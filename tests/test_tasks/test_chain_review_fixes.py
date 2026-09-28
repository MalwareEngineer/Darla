"""Fixes from reviewing a live investigation chain.

A DocuSign lure behind a Mailchimp click-tracker produced 10 kits where 3
were useful, sat IN_PROGRESS after finishing, and lost 30 s per kit to a
dispatch race:

* API + chain-crawler dispatched Celery chains before the kit row was
  committed -> "Kit ... not found" -> 30 s retry (only one retry).
* A render that ended as a duplicate was the last kit to finish; that path
  never ran the completion check.
* The click-tracker -> phish redirect looked like relay rotation, so the
  browser re-rendered the root four more times.
* Cloudflare's analytics beacon (/beacon.min.js/v31...) was classified as
  a landing page, spawned a kit, and the thin-results net browser-rendered
  the script — twice, the second time from a render kit.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from darla.analysis.js_fetcher import ExternalJSFetcher
from darla.analysis.patterns import is_benign_url
from darla.services.dispatch import commit_then_dispatch
from darla.tasks import analysis as analysis_module
from darla.tasks import browser as browser_module
from darla.tasks.analysis import _looks_like_html
from darla.tasks.browser import _complete_investigation_if_done, _known_landing_hosts

BEACON = "https://static.cloudflareinsights.com/beacon.min.js/v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495"


# ---------------------------------------------------------------------------
# Dispatch only after commit
# ---------------------------------------------------------------------------

async def test_commit_then_dispatch_orders_commit_first() -> None:
    events: list[str] = []
    db = MagicMock()
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))
    chain = MagicMock()
    chain.apply_async.side_effect = lambda: events.append("dispatch") or "task"

    assert await commit_then_dispatch(db, chain) == "task"
    assert events == ["commit", "dispatch"]


def test_api_services_never_dispatch_directly() -> None:
    from darla.services import investigation_service, kit_service

    for module in (kit_service, investigation_service):
        src = inspect.getsource(module)
        assert "chain.apply_async()" not in src, module.__name__
        assert "commit_then_dispatch" in src, module.__name__


def test_chain_crawler_commits_before_dispatching(monkeypatch) -> None:
    from darla.analysis.chain_crawler import ChainCrawler

    events: list[str] = []

    class _DB:
        def query(self, *_):
            return self

        def filter(self, *_):
            return self

        def all(self):
            return []

        def add(self, kit):
            self._last = kit

        def flush(self):
            self._last.id = uuid.uuid4()

        def commit(self):
            events.append("commit")

    fake_chain = MagicMock()
    fake_chain.return_value.apply_async.side_effect = lambda: events.append("dispatch")
    monkeypatch.setattr(analysis_module, "build_analysis_chain", fake_chain)

    @dataclass
    class _Link:
        url: str
        source: str = "redirect"
        score: float = 0.9

    ids = ChainCrawler(_DB()).submit_child_kits(
        parent_kit_id=uuid.uuid4(), investigation_id=uuid.uuid4(),
        scored_links=[_Link("https://a.test/"), _Link("https://b.test/")],
        current_depth=0,
    )
    assert len(ids) == 2
    assert events == ["commit", "dispatch", "dispatch"]


# ---------------------------------------------------------------------------
# Investigation completion on duplicate renders
# ---------------------------------------------------------------------------

@dataclass
class _KitStub:
    investigation_id: uuid.UUID | None = None
    source_url: str = "https://us.list-manage.test/track?e=abc"
    id: uuid.UUID = field(default_factory=uuid.uuid4)


def test_duplicate_render_runs_completion_check() -> None:
    inv = uuid.uuid4()
    with patch.object(analysis_module, "_try_complete_investigation") as check:
        _complete_investigation_if_done(MagicMock(), _KitStub(investigation_id=inv))
    check.assert_called_once()
    assert check.call_args == call(check.call_args.args[0], inv)


def test_feed_render_without_investigation_skips_check() -> None:
    with patch.object(analysis_module, "_try_complete_investigation") as check:
        _complete_investigation_if_done(MagicMock(), _KitStub())
    check.assert_not_called()


def test_both_duplicate_return_paths_check_completion() -> None:
    """stuck-at-gate and sibling-duplicate both return early from
    browser_download_kit; each must run the check (the sibling path only
    after its re-dispatch decision)."""
    src = inspect.getsource(browser_module.browser_download_kit)
    assert src.count("_complete_investigation_if_done(db, child_kit)") == 2
    sibling = src[src.index("# Sibling duplicate"):]
    assert sibling.index("precreate_browser_render_child_kit") < sibling.index(
        "_complete_investigation_if_done",
    )


# ---------------------------------------------------------------------------
# Relay rotation vs an ordinary redirect
# ---------------------------------------------------------------------------

class _ScalarDB:
    def __init__(self, value):
        self._value = value

    def query(self, *_):
        return self

    def filter(self, *_):
        return self

    def scalar(self):
        return self._value


def test_redirect_chain_hosts_are_known_landings() -> None:
    chain = {
        "final_url": "https://fastdocsign.phish.test/docusign-agreement-signature/tok",
        "hops": [
            {"url": "https://us.list-manage.test/track?e=abc",
             "location": "https://mid.tracker.test/r"},
            {"url": "https://mid.tracker.test/r", "location": "/relative/path"},
        ],
    }
    hosts = _known_landing_hosts(_ScalarDB(chain), _KitStub())
    assert hosts == {"us.list-manage.test", "mid.tracker.test", "fastdocsign.phish.test"}


def test_no_redirect_chain_falls_back_to_source_host() -> None:
    assert _known_landing_hosts(_ScalarDB(None), _KitStub()) == {"us.list-manage.test"}


def test_relay_rerender_uses_known_landing_hosts() -> None:
    src = inspect.getsource(browser_module.browser_download_kit)
    assert "not in _known_landing_hosts(db, parent_kit)" in src


# ---------------------------------------------------------------------------
# Thin-results browser net
# ---------------------------------------------------------------------------

def test_thin_results_net_skips_browser_render_kits() -> None:
    src = inspect.getsource(analysis_module.finalize_kit)
    assert 'kit.discovery_method != "browser_render"' in src


def test_minified_script_does_not_sniff_as_html(tmp_path) -> None:
    js = tmp_path / "v31edd6df95cf4e85bb4c19e7a9bdbcba1788362987495"
    js.write_bytes(b"!function(){var e=window.__cfBeacon||{};" + b"x" * 30000)
    assert not _looks_like_html(js, 4096)


def test_lure_with_long_leading_comment_sniffs_as_html(tmp_path) -> None:
    page = tmp_path / "agreement2026-2027"
    page.write_bytes(b"<!-- " + b"x" * 1500 + b" -->\n<html><body>lure</body></html>")
    assert not _looks_like_html(page)          # default 512-byte window misses it
    assert _looks_like_html(page, 4096)        # Tier B's window catches it


# ---------------------------------------------------------------------------
# Script URLs are not landing pages
# ---------------------------------------------------------------------------

@pytest.fixture
def fetcher() -> ExternalJSFetcher:
    return ExternalJSFetcher.__new__(ExternalJSFetcher)


@pytest.mark.parametrize(("url", "kind"), [
    (BEACON, "js"),
    ("https://cdn.test/app/main.js/v2", "js"),
    ("https://cdn.test/app/main.js", "js"),
    ("https://phish.test/", "terminal"),
    ("https://phish.test/login", "terminal"),
    ("https://phish.test/o/oauth2/deviceauth", "terminal"),
    ("https://phish.test/index.html", "terminal"),
])
def test_classify_url(fetcher, url, kind) -> None:
    assert fetcher._classify_url(url) == kind


def test_cloudflare_web_analytics_is_benign() -> None:
    assert is_benign_url(BEACON)


def test_urlparse_is_not_shadowed_inside_browser_download_kit() -> None:
    """A function-local ``from urllib.parse import urlparse`` inside one
    branch made ``urlparse`` local to the whole task, so any use outside
    that branch could raise UnboundLocalError."""
    code = browser_module.browser_download_kit.run.__code__
    assert "urlparse" not in code.co_varnames
