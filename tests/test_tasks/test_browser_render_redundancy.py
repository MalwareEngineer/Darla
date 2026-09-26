"""Browser-render redundancy checks that run before analysis.

``download_kit`` dispatches Tier A browser renders (JS loader, embedded
Turnstile, OAuth handoff) before ``compute_hashes`` can dedup the kit,
and a queued render can't be recalled.  Real-world case: investigation
f3aaf9af (vectorventure.cfd) held 10 kits where 6 sufficed — a redirect
child re-rendered the page its parent's browser render had already
captured, and the nonce-varied render spawned 4 more duplicate children.

``find_redundant_render_reason`` is the guard; ``find_sha256_match`` is
the investigation-preferring lookup shared by ``compute_hashes`` and the
browser dedup.  Both are pure queries, so they run against an in-memory
SQLite ``kits`` table — no Postgres, Celery, or Camoufox.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import darla.models  # noqa: F401 — register every mapper Kit relates to
from darla.models.kit import Kit, KitStatus
from darla.tasks.browser import (
    EMPTY_SHA256,
    find_redundant_render_reason,
    find_sha256_match,
)

_SHA_A = "a" * 64
_SHA_B = "b" * 64


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Kit.__table__.create(engine)
    with Session(engine) as session:
        yield session


def _kit(db, **kw) -> Kit:
    kw.setdefault("source_url", "https://example.test/")
    kw.setdefault("status", KitStatus.ANALYZED)
    kit = Kit(**kw)
    db.add(kit)
    db.flush()
    return kit


# ---------------------------------------------------------------------------
# Rule 1 — same-investigation SHA256 duplicate
# ---------------------------------------------------------------------------

def test_same_investigation_sha256_duplicate_is_redundant(db) -> None:
    inv = uuid.uuid4()
    existing = _kit(db, investigation_id=inv, sha256=_SHA_A)
    kit = _kit(db, investigation_id=inv, status=KitStatus.DOWNLOADED)

    reason = find_redundant_render_reason(db, kit, _SHA_A)

    assert reason is not None
    assert str(existing.id) in reason


def test_cross_investigation_sha256_match_still_renders(db) -> None:
    """A match in another investigation is a correlation signal —
    compute_hashes keeps analyzing, so the render must still happen."""
    _kit(db, investigation_id=uuid.uuid4(), sha256=_SHA_A)
    kit = _kit(db, investigation_id=uuid.uuid4(), status=KitStatus.DOWNLOADED)

    assert find_redundant_render_reason(db, kit, _SHA_A) is None


def test_empty_file_hash_never_counts(db) -> None:
    inv = uuid.uuid4()
    _kit(db, investigation_id=inv, sha256=EMPTY_SHA256)
    kit = _kit(db, investigation_id=inv, status=KitStatus.DOWNLOADED)

    assert find_redundant_render_reason(db, kit, EMPTY_SHA256) is None


def test_kit_does_not_match_itself(db) -> None:
    """Re-runs: the kit's own stale sha256 must not block its render."""
    kit = _kit(db, investigation_id=uuid.uuid4(), sha256=_SHA_A)

    assert find_redundant_render_reason(db, kit, _SHA_A) is None


def test_feed_kits_are_never_checked(db) -> None:
    _kit(db, investigation_id=None, sha256=_SHA_A)
    kit = _kit(db, investigation_id=None, status=KitStatus.DOWNLOADED)

    assert find_redundant_render_reason(db, kit, _SHA_A) is None


# ---------------------------------------------------------------------------
# Rule 2 — redirect child of an already-rendered parent
# ---------------------------------------------------------------------------

def _parent_with_render(db, inv, **render_kw) -> Kit:
    parent = _kit(db, investigation_id=inv, sha256=_SHA_B)
    render_kw.setdefault("status", KitStatus.DOWNLOADING)
    _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="browser_render", chain_depth=1, **render_kw,
    )
    return parent


@pytest.mark.parametrize(
    "status", [KitStatus.DOWNLOADING, KitStatus.ANALYZING, KitStatus.ANALYZED],
)
def test_redirect_child_of_rendered_parent_is_redundant(db, status) -> None:
    """In-flight and finished parent renders both cover the redirect."""
    inv = uuid.uuid4()
    parent = _parent_with_render(db, inv, status=status)
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="redirect", chain_depth=1,
        status=KitStatus.DOWNLOADED,
    )

    reason = find_redundant_render_reason(db, child, _SHA_A)

    assert reason is not None
    assert "already followed this redirect" in reason


def test_parent_render_failed_as_duplicate_still_counts(db) -> None:
    """A render FAILED by dedup reached the page fine — still covers it."""
    inv = uuid.uuid4()
    parent = _parent_with_render(
        db, inv, status=KitStatus.FAILED, duplicate_of_kit_id=uuid.uuid4(),
    )
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="redirect", status=KitStatus.DOWNLOADED,
    )

    assert find_redundant_render_reason(db, child, _SHA_A) is not None


def test_parent_render_errored_gives_child_its_own_attempt(db) -> None:
    """A render that FAILED on error (timeout, crash) captured nothing."""
    inv = uuid.uuid4()
    parent = _parent_with_render(
        db, inv, status=KitStatus.FAILED, error_message="Browser error: timeout",
    )
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="redirect", status=KitStatus.DOWNLOADED,
    )

    assert find_redundant_render_reason(db, child, _SHA_A) is None


def test_redirect_child_of_unrendered_parent_renders(db) -> None:
    inv = uuid.uuid4()
    parent = _kit(db, investigation_id=inv, sha256=_SHA_B)
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="redirect", status=KitStatus.DOWNLOADED,
    )

    assert find_redundant_render_reason(db, child, _SHA_A) is None


@pytest.mark.parametrize("method", ["eml_link", "qr_code", "svg_chain_terminal"])
def test_non_redirect_children_are_not_covered_by_parent_render(db, method) -> None:
    """Only redirects are followed by the parent's render.  An EML link
    or QR destination is a separate navigation the browser never took."""
    inv = uuid.uuid4()
    parent = _parent_with_render(db, inv)
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method=method, status=KitStatus.DOWNLOADED,
    )

    assert find_redundant_render_reason(db, child, _SHA_A) is None


def test_sha256_none_skips_rule_one_but_applies_rule_two(db) -> None:
    """finalize_kit's Tier B check passes sha256=None (dups never reach
    finalize), so only the redirect rule applies there."""
    inv = uuid.uuid4()
    _kit(db, investigation_id=inv, sha256=_SHA_A)
    parent = _parent_with_render(db, inv)
    child = _kit(
        db, investigation_id=inv, parent_kit_id=parent.id,
        discovery_method="redirect", status=KitStatus.DOWNLOADED,
    )
    orphan = _kit(db, investigation_id=inv, status=KitStatus.DOWNLOADED)

    assert find_redundant_render_reason(db, child, None) is not None
    assert find_redundant_render_reason(db, orphan, None) is None


# ---------------------------------------------------------------------------
# find_sha256_match — same investigation wins over cross-investigation
# ---------------------------------------------------------------------------

def test_sha256_match_prefers_same_investigation(db) -> None:
    """With both a cross- and same-investigation match present, the
    unordered lookup used to be able to return the cross-investigation
    row, downgrading real redundancy to correlation."""
    inv = uuid.uuid4()
    _kit(db, investigation_id=uuid.uuid4(), sha256=_SHA_A)  # inserted first
    same = _kit(db, investigation_id=inv, sha256=_SHA_A)
    kit = _kit(db, investigation_id=inv)

    assert find_sha256_match(db, _SHA_A, kit.id, inv).id == same.id


def test_sha256_match_falls_back_to_cross_investigation(db) -> None:
    other = _kit(db, investigation_id=uuid.uuid4(), sha256=_SHA_A)
    kit = _kit(db, investigation_id=uuid.uuid4())

    assert find_sha256_match(db, _SHA_A, kit.id, kit.investigation_id).id == other.id


def test_sha256_match_excludes_self_and_misses_cleanly(db) -> None:
    kit = _kit(db, investigation_id=uuid.uuid4(), sha256=_SHA_A)

    assert find_sha256_match(db, _SHA_A, kit.id, kit.investigation_id) is None


def test_sha256_match_treats_null_investigations_as_same(db) -> None:
    """Feed kits (NULL investigation) keep collapsing into each other."""
    feed = _kit(db, investigation_id=None, sha256=_SHA_A)
    kit = _kit(db, investigation_id=None)

    assert find_sha256_match(db, _SHA_A, kit.id, None).id == feed.id
