"""Cleanup of on-disk artifacts for same-investigation duplicate kits.

When pool-enumeration or CF-Turnstile re-render loops produce
TLSH-distance-0 sibling kits, their per-kit directories
(page.html / requests.json / _screenshots / _browser_resources) are
byte-identical copies of the canonical sibling's content.  Once the
investigation is COMPLETED and a 24h grace window has passed, the
``cleanup_completed_investigation_duplicates`` task deletes those
directories while preserving the Kit rows + ``duplicate_of_kit_id``
pointer for audit.

The function is exercised end-to-end against a real temp filesystem
and a stub SQLAlchemy session — that's the failure surface that
matters (rmtree against a real directory, kit row mutations under a
transaction).  The defense-in-depth invariants (cross-investigation
filter, SHA256-equality check, missing-canonical guard) are the
high-value test cases since they prevent data loss.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from darla.models.investigation import InvestigationStatus
from darla.models.kit import KitStatus

# ---------------------------------------------------------------------------
# Stub harness — minimal session-mock that records mutations + supports
# the exact query shapes the cleanup task issues.
# ---------------------------------------------------------------------------

@dataclass
class _StubInvestigation:
    id: uuid.UUID
    status: InvestigationStatus
    updated_at: datetime


@dataclass
class _StubKit:
    id: uuid.UUID
    investigation_id: uuid.UUID | None
    status: KitStatus
    duplicate_of_kit_id: uuid.UUID | None = None
    local_path: str | None = None
    sha256: str | None = None
    error_message: str | None = None


@dataclass
class _StubDB:
    kits: list[_StubKit] = field(default_factory=list)
    investigations: list[_StubInvestigation] = field(default_factory=list)
    committed: bool = False
    rolled_back: bool = False

    # ------------------------------------------------------------------
    # Query support — only what the cleanup task actually issues.
    # ------------------------------------------------------------------
    def scalars(self, _stmt):
        # The cleanup task's only ``scalars(...)`` call selects FAILED
        # duplicate kits joined to COMPLETED investigations older than
        # the cutoff.  We re-derive that here from the stored data so
        # the test exercises the same filter shape.
        cutoff = self._extract_cutoff_from_stmt(_stmt)
        completed_inv_ids = {
            i.id for i in self.investigations
            if i.status == InvestigationStatus.COMPLETED
            and i.updated_at < cutoff
        }
        rows = [
            k for k in self.kits
            if k.status == KitStatus.FAILED
            and k.duplicate_of_kit_id is not None
            and k.local_path is not None
            and k.investigation_id in completed_inv_ids
        ]
        return _StubScalars(rows)

    def get(self, _model, kit_id):
        for k in self.kits:
            if k.id == kit_id:
                return k
        return None

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass

    @staticmethod
    def _extract_cutoff_from_stmt(_stmt) -> datetime:
        # We don't introspect the SQL — the cleanup task computes
        # cutoff as ``datetime.now(UTC) - timedelta(hours=24)`` (the
        # default min_age_hours).  All tests in this file call the
        # task with the default 24h grace, so we mirror that here.
        return datetime.now(UTC) - timedelta(hours=24)


class _StubScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


@pytest.fixture()
def patched_db(monkeypatch):
    """Patch ``get_sync_db`` so the cleanup task sees our stub."""
    from darla.tasks import recovery as recovery_module

    db = _StubDB()
    monkeypatch.setattr(recovery_module, "get_sync_db", lambda: db)
    return db


def _make_kit_dir(tmp_path: Path, kit_id: uuid.UUID, total_bytes: int = 4096) -> Path:
    """Create a realistic per-kit on-disk structure (page.html +
    requests.json + a screenshot dir) summing to ~total_bytes."""
    kit_dir = tmp_path / str(kit_id)
    kit_dir.mkdir(parents=True)
    half = total_bytes // 2
    (kit_dir / "page.html").write_bytes(b"x" * half)
    (kit_dir / "requests.json").write_bytes(b"y" * (half // 2))
    screenshots = kit_dir / "_screenshots"
    screenshots.mkdir()
    (screenshots / "00_full.png").write_bytes(b"z" * (half // 2))
    return kit_dir


# ---------------------------------------------------------------------------
# Happy path — same-investigation TLSH-0 dup gets tombstoned
# ---------------------------------------------------------------------------

def test_cleanup_tombstones_same_investigation_dup(tmp_path, patched_db):
    """The canonical pool-enum case: COMPLETED investigation, FAILED
    duplicate sibling with matching SHA256, fully on disk.  After
    cleanup the directory is gone and the kit row's local_path is
    cleared, but duplicate_of_kit_id and error_message survive."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()
    sha = "a" * 64

    # Investigation completed 48h ago — well past the 24h grace.
    patched_db.investigations.append(_StubInvestigation(
        id=inv_id,
        status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id, total_bytes=8192)
    dup_dir = _make_kit_dir(tmp_path, dup_id, total_bytes=8192)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256=sha,
        local_path=str(dup_dir / "page.html"),
        error_message=f"Sibling duplicate of kit {canon_id} (TLSH distance 0)",
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 1
    assert result["deleted_bytes"] > 0
    assert result["skipped"] == 0

    # Duplicate's directory is gone.
    assert not dup_dir.exists()
    # Canonical's directory is untouched.
    assert canon_dir.exists()
    assert (canon_dir / "page.html").exists()

    # Tombstone semantics on the row: local_path cleared, but the
    # audit pointer + error message survive.
    dup = next(k for k in patched_db.kits if k.id == dup_id)
    assert dup.local_path is None
    assert dup.duplicate_of_kit_id == canon_id
    assert "Sibling duplicate" in dup.error_message
    assert dup.sha256 == sha  # hashes intact for SHA256 search

    assert patched_db.committed


# ---------------------------------------------------------------------------
# Defense-in-depth — cross-investigation correlation must NEVER be cleaned
# ---------------------------------------------------------------------------

def test_cleanup_skips_cross_investigation_correlation(tmp_path, patched_db):
    """Cross-investigation correlation kits are status=ANALYZED so the
    primary FAILED filter excludes them.  This test exercises the
    same-investigation join check — even if a kit somehow ended up
    FAILED with a cross-investigation duplicate_of pointer, cleanup
    must refuse to touch it."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_a = uuid.uuid4()
    inv_b = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()
    sha = "b" * 64

    patched_db.investigations.append(_StubInvestigation(
        id=inv_b, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    dup_dir = _make_kit_dir(tmp_path, dup_id)

    # Canonical lives in investigation A; duplicate is FAILED in
    # investigation B (the case the safety check guards against).
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_a, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_b, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256=sha,
        local_path=str(dup_dir / "page.html"),
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 0
    assert result["skipped"] == 1
    # Both directories survive — we don't touch cross-investigation data.
    assert dup_dir.exists()
    assert canon_dir.exists()


# ---------------------------------------------------------------------------
# Defense-in-depth — SHA256 mismatch means TLSH said similar but bytes differ
# ---------------------------------------------------------------------------

def test_cleanup_skips_when_sha256_differs(tmp_path, patched_db):
    """TLSH distance 0 doesn't guarantee byte-equality.  When SHA256
    of the duplicate differs from the canonical's, preserve the files
    — this is the case where we'd lose unique forensic content."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    dup_dir = _make_kit_dir(tmp_path, dup_id)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256="c" * 64, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256="d" * 64,
        local_path=str(dup_dir / "page.html"),
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 0
    assert result["skipped"] == 1
    assert dup_dir.exists()


def test_cleanup_skips_when_canonical_missing(tmp_path, patched_db):
    """If the canonical kit was somehow deleted, we can't verify
    SHA256 equality — refuse to clean rather than guessing."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()  # not added to db
    dup_id = uuid.uuid4()

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    dup_dir = _make_kit_dir(tmp_path, dup_id)
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256="e" * 64,
        local_path=str(dup_dir / "page.html"),
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 0
    assert result["skipped"] == 1
    assert dup_dir.exists()


# ---------------------------------------------------------------------------
# Grace window — recently-completed investigations are skipped
# ---------------------------------------------------------------------------

def test_cleanup_respects_grace_window(tmp_path, patched_db):
    """An investigation completed 1h ago must NOT have its duplicates
    cleaned at the default 24h grace.  Operators need time to inspect."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()
    sha = "f" * 64

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=1),  # too fresh
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    dup_dir = _make_kit_dir(tmp_path, dup_id)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256=sha,
        local_path=str(dup_dir / "page.html"),
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 0
    # Files preserved — investigation was inside the grace window.
    assert dup_dir.exists()


def test_cleanup_skips_inprogress_investigations(tmp_path, patched_db):
    """IN_PROGRESS investigations must never have their duplicates
    cleaned, regardless of age — chains may still be running."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()
    sha = "1" * 64

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.IN_PROGRESS,
        updated_at=datetime.now(UTC) - timedelta(days=10),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    dup_dir = _make_kit_dir(tmp_path, dup_id)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256=sha,
        local_path=str(dup_dir / "page.html"),
    ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 0
    assert dup_dir.exists()


# ---------------------------------------------------------------------------
# Edge cases — directory already missing, multiple dups in one investigation
# ---------------------------------------------------------------------------

def test_cleanup_handles_already_missing_directory(tmp_path, patched_db):
    """If a kit's directory is gone (manual cleanup, lost volume, etc.),
    the task should clear ``local_path`` so it doesn't keep retrying,
    but not crash and not double-count."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_id = uuid.uuid4()
    sha = "2" * 64

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    patched_db.kits.append(_StubKit(
        id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
        duplicate_of_kit_id=canon_id, sha256=sha,
        # local_path points at a path that doesn't exist on disk
        local_path=str(tmp_path / "ghost" / "page.html"),
    ))

    cleanup_completed_investigation_duplicates(min_age_hours=24)

    # Not counted as a deletion (no bytes freed) but local_path cleared.
    dup = next(k for k in patched_db.kits if k.id == dup_id)
    assert dup.local_path is None


def test_cleanup_processes_multiple_dups_in_one_pool(tmp_path, patched_db):
    """A pool-enum cycle that produced 3 sibling duplicates should
    have all 3 cleaned in one task run."""
    from darla.tasks.recovery import cleanup_completed_investigation_duplicates

    inv_id = uuid.uuid4()
    canon_id = uuid.uuid4()
    dup_ids = [uuid.uuid4() for _ in range(3)]
    sha = "3" * 64

    patched_db.investigations.append(_StubInvestigation(
        id=inv_id, status=InvestigationStatus.COMPLETED,
        updated_at=datetime.now(UTC) - timedelta(hours=48),
    ))
    canon_dir = _make_kit_dir(tmp_path, canon_id)
    patched_db.kits.append(_StubKit(
        id=canon_id, investigation_id=inv_id, status=KitStatus.ANALYZED,
        sha256=sha, local_path=str(canon_dir / "page.html"),
    ))
    dup_dirs = []
    for dup_id in dup_ids:
        d = _make_kit_dir(tmp_path, dup_id)
        dup_dirs.append(d)
        patched_db.kits.append(_StubKit(
            id=dup_id, investigation_id=inv_id, status=KitStatus.FAILED,
            duplicate_of_kit_id=canon_id, sha256=sha,
            local_path=str(d / "page.html"),
        ))

    result = cleanup_completed_investigation_duplicates(min_age_hours=24)

    assert result["deleted_kits"] == 3
    assert all(not d.exists() for d in dup_dirs)
    assert canon_dir.exists()
