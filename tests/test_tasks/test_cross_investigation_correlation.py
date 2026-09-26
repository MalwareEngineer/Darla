"""Cross-investigation SHA256 correlation behavior.

When two investigations independently render the same attacker
infrastructure (an AITM proxy serving identical bytes to multiple
victim chains is the canonical example), we want both kits to:

  * complete the full analysis chain (each investigation gets its
    own IOC / YARA / similarity rows tied to ITS investigation), and
  * carry a soft pointer (``duplicate_of_kit_id``) back to the
    canonical sibling so the campaign-correlation signal isn't lost.

The previous behavior collapsed investigation B's kit into a FAILED
duplicate with hashes nulled — losing analysis data for B and making
the kit invisible to SHA256/TLSH search.  These tests guard the new
contract.

Same-investigation duplicates (CF Turnstile re-render loops, relay
pool exhaustion, etc.) keep their FAILED-redundancy semantics — those
ARE redundant work, not correlation.

The decision lives in two places: ``compute_hashes`` (analysis.py) for
all kits and the dedup block of ``browser_download_kit`` (browser.py)
for browser-rendered kits specifically.  Both implementations follow
the same investigation-scoping rule; these tests assert the rule
shape rather than re-running the whole celery harness.
"""

from __future__ import annotations

import inspect

from darla.tasks import analysis as analysis_module
from darla.tasks import browser as browser_module

# ---------------------------------------------------------------------------
# Same-investigation matches must keep the FAILED-redundancy branch
# ---------------------------------------------------------------------------

def test_compute_hashes_keeps_same_investigation_failed_branch() -> None:
    """The same-investigation case is REDUNDANT WORK in one chain
    (e.g. Cloudflare Turnstile re-rendering the same gate page).
    Mark FAILED + set duplicate_of_kit_id; do not run analysis on it.

    Locks in: source still references both ``KitStatus.FAILED`` AND
    ``duplicate_of_kit_id`` in the same-investigation branch, so a
    refactor can't silently lose the FAILED status (which would burn
    CPU running the chain on redundant content).
    """
    src = inspect.getsource(analysis_module.compute_hashes)
    assert "same_investigation" in src
    # Same-investigation branch must keep both signals.
    assert "KitStatus.FAILED" in src
    assert "duplicate_of_kit_id" in src


def test_compute_hashes_cross_investigation_does_not_mark_failed() -> None:
    """The whole point of this fix: cross-investigation matches must
    NOT mark FAILED.  Source-level guard: there must be a code path
    where ``duplicate_of_kit_id`` is set without an accompanying
    ``KitStatus.FAILED`` assignment in the same branch."""
    src = inspect.getsource(analysis_module.compute_hashes)
    # The cross-investigation branch is what runs after the
    # ``if same_investigation:`` block returns; it must include the
    # correlation log message that indicates analysis proceeds.
    assert "cross-investigation correlation" in src
    assert "proceeding with full analysis" in src


# ---------------------------------------------------------------------------
# browser.py mirror of the same rule
# ---------------------------------------------------------------------------

def test_browser_download_kit_distinguishes_same_vs_cross_investigation() -> None:
    """Cross-chain SHA256 dedup in browser.py must apply the same rule
    — same-investigation match → FAILED, cross-investigation match →
    correlation pointer + continued analysis."""
    src = inspect.getsource(browser_module.browser_download_kit)
    assert "same_investigation" in src
    assert "cross-investigation correlation" in src


def test_browser_dedup_does_not_null_hashes_anymore() -> None:
    """The previous implementation set ``child_kit.sha256 = None`` on
    duplicates to dodge the UNIQUE constraint on ix_kits_sha256.  With
    the constraint dropped (migration w3s9t0u1v2n4) we keep hashes
    intact — duplicate kits should remain searchable by SHA256/TLSH so
    operators can find every encounter of a given asset, not just the
    canonical one.
    """
    src = inspect.getsource(browser_module.browser_download_kit)
    # The exact sentinel that would re-introduce the bug.
    assert "child_kit.sha256 = None" not in src
    assert "child_kit.tlsh = None" not in src


# ---------------------------------------------------------------------------
# Schema guard: kits.sha256 must NOT be UNIQUE
# ---------------------------------------------------------------------------

def test_kit_sha256_column_is_not_unique() -> None:
    """The migration drops the UNIQUE on ``ix_kits_sha256``.  This test
    enforces that the model declaration matches — a future ``unique=True``
    re-add would resurrect the UniqueViolation that drove this fix.
    """
    from darla.models.kit import Kit

    sha256_col = Kit.__table__.c.sha256
    assert sha256_col.unique is not True, (
        "kits.sha256 must NOT be UNIQUE — cross-investigation kits "
        "legitimately share a hash; the constraint was dropped in "
        "migration w3s9t0u1v2n4 for that reason."
    )
    # Index should still exist for lookup performance.
    assert sha256_col.index is True


# ---------------------------------------------------------------------------
# Correlation pointer surfaces in the task return value
# ---------------------------------------------------------------------------

def test_browser_download_kit_emits_correlated_with_in_result() -> None:
    """When a kit is cross-investigation correlated, the post-download
    chain prev_result should carry ``correlated_with`` so downstream
    UI / consumers can render the link prominently rather than having
    to query duplicate_of_kit_id separately."""
    src = inspect.getsource(browser_module.browser_download_kit)
    assert '"correlated_with"' in src
