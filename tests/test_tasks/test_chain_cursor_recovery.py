"""Chain-cursor recovery tests.

The post-download analysis chain interleaves the ``analysis`` and
``browser`` queues (e.g. ``execute_svgs_active`` is on the browser
queue at step 7).  Any queue-level intervention — a purge, a worker
restart, a broker reconnect — that drops a step task in the middle of
a chain leaves the kit in ``DOWNLOADED`` with the work that already
ran intact but no Celery message to drive the rest.

``Kit.chain_cursor`` records "step that started but may not have
completed" via a ``task_prerun`` signal in ``tasks/analysis.py``.  The
``recover_chain_cursors`` beat job picks up kits stalled on a cursor
and dispatches a partial chain starting AT the cursor.  These tests
guard the slicing logic + step-name registry so a refactor that adds
a new chain step (or moves one across queues) can't silently break
the resume path.
"""

from __future__ import annotations

from darla.tasks.analysis import (
    _CHAIN_STEP_NAME_MAP,
    _CHAIN_STEP_ORDER,
    post_download_steps_from_cursor,
)

# ---------------------------------------------------------------------------
# Step registry consistency — _CHAIN_STEP_NAME_MAP and _CHAIN_STEP_ORDER
# must agree, and they must cover every step that _post_download_steps()
# yields.  Without this guard the cursor signal silently misses new steps.
# ---------------------------------------------------------------------------

def test_step_order_matches_name_map_values_exactly() -> None:
    """Both data structures encode the same ordering of step short names.
    A drift between them would mean the prerun signal records cursors
    that the resume path can't slice from."""
    assert tuple(_CHAIN_STEP_NAME_MAP.values()) == _CHAIN_STEP_ORDER


def test_step_order_matches_post_download_steps_invocation_order() -> None:
    """Ground truth: ``_post_download_steps()`` is what actually gets
    dispatched.  Every signature it returns must have a matching entry
    in ``_CHAIN_STEP_NAME_MAP``.  This catches the "added a step,
    forgot to register it" failure mode."""
    from darla.tasks.analysis import _post_download_steps

    steps = _post_download_steps()
    actual_names = [s.task for s in steps]  # signature.task = task name
    assert actual_names == list(_CHAIN_STEP_NAME_MAP.keys()), (
        "_post_download_steps() invocation order must match "
        "_CHAIN_STEP_NAME_MAP key order — registry drift will silently "
        "break chain_cursor recovery"
    )


# ---------------------------------------------------------------------------
# post_download_steps_from_cursor — the slicing primitive
# ---------------------------------------------------------------------------

def test_resume_from_first_step_returns_full_chain() -> None:
    """Cursor at the first step → resume runs everything from scratch
    (idempotent re-execution; cheaper than going back to download_kit
    because we keep local_path + sha256 etc.)."""
    steps = post_download_steps_from_cursor("compute_hashes")
    assert len(steps) == len(_CHAIN_STEP_ORDER)


def test_resume_from_middle_step_returns_tail() -> None:
    """Cursor at step 7 (execute_svgs_active) — the cross-queue step
    that broke the chain in the maintenance incident — resume should
    re-run from there to the end (8 steps remaining)."""
    cursor = "execute_svgs_active"
    cursor_index = _CHAIN_STEP_ORDER.index(cursor)
    expected_remaining = len(_CHAIN_STEP_ORDER) - cursor_index

    steps = post_download_steps_from_cursor(cursor)
    assert len(steps) == expected_remaining
    # First signature returned matches the cursor task — we resume AT
    # it, not after, because the cursor records "started but maybe not
    # completed".  Idempotent re-execution is the contract.
    assert steps[0].task.endswith(cursor)


def test_resume_from_finalize_returns_just_finalize() -> None:
    """Cursor at the last step → resume runs only that step.  This is
    the case where finalize_kit started but its DB commit didn't land
    (e.g. process killed mid-finalize)."""
    steps = post_download_steps_from_cursor("finalize_kit")
    assert len(steps) == 1
    assert steps[0].task.endswith("finalize_kit")


def test_resume_from_unknown_cursor_returns_empty() -> None:
    """Defensive: a cursor we don't recognize must not crash and must
    NOT dispatch a chain (we can't slice it correctly)."""
    assert post_download_steps_from_cursor("not_a_real_step") == []


def test_resume_from_none_cursor_returns_empty() -> None:
    """Kits without ``chain_cursor`` set haven't entered the chain yet
    (or have completed cleanly).  No resume work to do."""
    assert post_download_steps_from_cursor(None) == []


def test_resume_from_empty_string_returns_empty() -> None:
    """Defensive: empty string is not a valid cursor."""
    assert post_download_steps_from_cursor("") == []


# ---------------------------------------------------------------------------
# Step name registry — every step we plan to recover must map a
# fully-qualified Celery task name to a short cursor name.  Drift here
# means cursors don't get recorded for that step.
# ---------------------------------------------------------------------------

def test_known_steps_map_to_short_names() -> None:
    """Verify the specific cross-queue step that broke the chain in the
    incident IS registered.  This is the regression guard."""
    assert (
        _CHAIN_STEP_NAME_MAP.get("darla.tasks.browser.execute_svgs_active")
        == "execute_svgs_active"
    )


def test_no_duplicate_short_names() -> None:
    """Short names are used as enum-ish cursor values; collisions would
    make slicing ambiguous."""
    short_names = list(_CHAIN_STEP_NAME_MAP.values())
    assert len(short_names) == len(set(short_names))


def test_chain_steps_span_analysis_and_browser_queues() -> None:
    """The whole point of cursor-based recovery is that we cross queues
    mid-chain.  If this ever stops being true, recovery isn't needed
    and we can simplify.  Until then, the test guards that we still
    have the cross-queue split."""
    queues_seen = set()
    for fq_name in _CHAIN_STEP_NAME_MAP:
        if fq_name.startswith("darla.tasks.analysis."):
            queues_seen.add("analysis")
        elif fq_name.startswith("darla.tasks.browser."):
            queues_seen.add("browser")
        elif fq_name.startswith("darla.tasks.chain."):
            queues_seen.add("analysis")  # chain.* routes to analysis queue
    # Analysis queue + browser queue must both be represented.
    assert "analysis" in queues_seen
    assert "browser" in queues_seen
