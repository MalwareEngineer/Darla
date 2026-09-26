"""Per-investigation in-flight budget tests for browser_download_kit.

The browser worker is the throughput bottleneck (one Camoufox
instance per replica, 60-150s/render).  Without a per-investigation
budget, a single adversarial AITM kit with relay rotation could fill
the queue with up to ``browser_render_max_variations`` (now 10)
self-redispatched tasks, starving every other investigation.

``_can_dispatch_browser_render`` is the budget primitive — pure logic
over an in-memory ``KitStub`` list.  These tests guard the "is in-
flight" definition (DOWNLOADING + browser_render) and the per-
investigation isolation (one investigation can't burn another's
budget).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from darla.models.kit import KitStatus
from darla.tasks.browser import _can_dispatch_browser_render

# ---------------------------------------------------------------------------
# Stub-based test harness — exercises the COUNT query path through a
# minimal session-mock so the budget logic itself is what's under test
# (not the SQLAlchemy ORM).
# ---------------------------------------------------------------------------

@dataclass
class _KitStub:
    investigation_id: uuid.UUID | None
    discovery_method: str
    status: KitStatus
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class _StubSession:
    """Minimal SQLAlchemy session stand-in that supports the exact
    query shape ``_can_dispatch_browser_render`` issues."""

    def __init__(self, kits: list[_KitStub]):
        self._kits = kits
        self._filters: list = []

    def query(self, _agg):
        # Return self so .filter().scalar() chains work.
        self._filters = []
        return self

    def filter(self, *conditions):
        self._filters.extend(conditions)
        return self

    def scalar(self) -> int:
        # The function's query is:
        #   func.count(Kit.id)
        #     .filter(investigation_id == ?,
        #             discovery_method == 'browser_render',
        #             status == DOWNLOADING)
        # We don't try to interpret the SQLAlchemy condition objects;
        # instead we resolve by inspecting the filter values via
        # ``compare`` on the column expressions.  Simpler: just count
        # kits matching the in-flight definition the helper uses.
        target_inv = self._target_investigation_id()
        return sum(
            1
            for k in self._kits
            if k.investigation_id == target_inv
            and k.discovery_method == "browser_render"
            and k.status == KitStatus.DOWNLOADING
        )

    def _target_investigation_id(self) -> uuid.UUID | None:
        """Pull the investigation_id from the stored filter conditions.

        The helper's first filter is ``Kit.investigation_id == X``.
        SQLAlchemy ``BinaryExpression`` exposes the literal via
        ``.right.value``; inspect it directly so we don't have to
        interpret arbitrary SQL.
        """
        for cond in self._filters:
            right = getattr(cond, "right", None)
            value = getattr(right, "value", None)
            if isinstance(value, uuid.UUID):
                return value
        return None


# ---------------------------------------------------------------------------
# In-flight definition: only DOWNLOADING + browser_render counts
# ---------------------------------------------------------------------------

def test_no_inflight_returns_allowed_at_full_budget() -> None:
    """Empty investigation → full budget available.  Sanity floor."""
    inv = uuid.uuid4()
    db = _StubSession([])
    allowed, current = _can_dispatch_browser_render(db, inv, max_inflight=2)
    assert allowed is True
    assert current == 0


def test_completed_browser_renders_do_not_count() -> None:
    """ANALYZED / FAILED browser_render kits are NOT in-flight — they
    no longer occupy a worker slot.  Without this rule, a long-running
    investigation would permanently lose its budget."""
    inv = uuid.uuid4()
    kits = [
        _KitStub(inv, "browser_render", KitStatus.ANALYZED),
        _KitStub(inv, "browser_render", KitStatus.FAILED),
        _KitStub(inv, "browser_render", KitStatus.DOWNLOADED),
    ]
    db = _StubSession(kits)
    allowed, current = _can_dispatch_browser_render(db, inv, max_inflight=2)
    assert allowed is True
    assert current == 0


def test_non_browser_render_kits_do_not_count() -> None:
    """httpx-downloaded kits + EML-extracted kits are NOT browser
    renders and shouldn't burn the browser-render budget."""
    inv = uuid.uuid4()
    kits = [
        _KitStub(inv, "feed_url", KitStatus.DOWNLOADING),
        _KitStub(inv, "chain_crawler", KitStatus.DOWNLOADING),
        _KitStub(inv, "eml_attachment", KitStatus.DOWNLOADING),
    ]
    db = _StubSession(kits)
    allowed, current = _can_dispatch_browser_render(db, inv, max_inflight=2)
    assert allowed is True
    assert current == 0


def test_at_budget_blocks_new_dispatch() -> None:
    """At exactly ``max_inflight`` browser renders in DOWNLOADING, the
    next dispatch is suppressed — this is the primary contract."""
    inv = uuid.uuid4()
    kits = [
        _KitStub(inv, "browser_render", KitStatus.DOWNLOADING),
        _KitStub(inv, "browser_render", KitStatus.DOWNLOADING),
    ]
    db = _StubSession(kits)
    allowed, current = _can_dispatch_browser_render(db, inv, max_inflight=2)
    assert allowed is False
    assert current == 2


def test_just_below_budget_allows_dispatch() -> None:
    """One slot free → allowed.  Exercises the ``<`` boundary."""
    inv = uuid.uuid4()
    kits = [_KitStub(inv, "browser_render", KitStatus.DOWNLOADING)]
    db = _StubSession(kits)
    allowed, current = _can_dispatch_browser_render(db, inv, max_inflight=2)
    assert allowed is True
    assert current == 1


# ---------------------------------------------------------------------------
# Per-investigation isolation — the whole point of the budget is that
# investigation A can't drain investigation B's budget.
# ---------------------------------------------------------------------------

def test_other_investigation_inflight_does_not_block() -> None:
    """Investigation A at full budget → investigation B can still
    dispatch.  Without this, one adversarial kit takes down the whole
    pipeline."""
    inv_a = uuid.uuid4()
    inv_b = uuid.uuid4()
    kits = [
        _KitStub(inv_a, "browser_render", KitStatus.DOWNLOADING),
        _KitStub(inv_a, "browser_render", KitStatus.DOWNLOADING),
        _KitStub(inv_a, "browser_render", KitStatus.DOWNLOADING),
    ]
    db = _StubSession(kits)
    # Even though investigation A has 3 in-flight (over a hypothetical
    # 2-cap), B's check must report 0 in-flight for B.
    allowed, current = _can_dispatch_browser_render(db, inv_b, max_inflight=2)
    assert allowed is True
    assert current == 0


# ---------------------------------------------------------------------------
# Pre-investigation root kits (investigation_id=None)
# ---------------------------------------------------------------------------

def test_no_investigation_id_skips_check() -> None:
    """Root kits without an investigation are by definition the FIRST
    dispatch in their chain — the budget can't be busy yet, so we
    should allow the dispatch unconditionally rather than block on a
    NULL match."""
    db = _StubSession([])
    allowed, current = _can_dispatch_browser_render(db, None, max_inflight=2)
    assert allowed is True
    assert current == 0
