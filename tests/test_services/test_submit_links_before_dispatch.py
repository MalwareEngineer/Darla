"""Submissions must link the investigation before the chain is dispatched.

``commit_then_dispatch`` publishes the analysis chain the moment it
commits, and a worker can dequeue it within milliseconds.  The submit
routes used to create the investigation *after* that call, so the
download worker loaded a root kit with ``investigation_id=NULL``: its
browser_render child was created unlinked (missing from the tree) and
the investigation, seeing only the already-finished root, was marked
COMPLETED while the render was still running.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from darla.models.kit import Kit
from darla.services.investigation_service import InvestigationService
from darla.services.kit_service import KitService
from darla.tasks import analysis as analysis_module


@pytest.fixture
def events(monkeypatch) -> list[str]:
    events: list[str] = []
    chain = MagicMock()
    chain.return_value.apply_async.side_effect = (
        lambda: events.append("dispatch") or MagicMock(id="task")
    )
    monkeypatch.setattr(analysis_module, "build_analysis_chain", chain)
    return events


def _db(events: list[str]) -> MagicMock:
    db = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))
    return db


def _prepare(events: list[str]):
    async def prepare(kit: Kit) -> None:
        assert isinstance(kit, Kit)
        events.append("prepare")

    return prepare


async def test_submit_kit_prepares_before_commit_and_dispatch(events) -> None:
    svc = KitService(_db(events))
    await svc.submit_kit("https://lure.test/", force=True, prepare=_prepare(events))
    assert events == ["prepare", "commit", "dispatch"]


async def test_submit_file_prepares_before_commit_and_dispatch(events) -> None:
    svc = KitService(_db(events))
    await svc.submit_file("a.eml", "/tmp/a.eml", prepare=_prepare(events))
    assert events == ["prepare", "commit", "dispatch"]


async def test_submit_bulk_prepares_each_kit_before_its_dispatch(events) -> None:
    svc = KitService(_db(events))
    svc._find_existing_kit = AsyncMock(return_value=None)
    await svc.submit_bulk(
        ["https://a.test/", "https://b.test/"], prepare=_prepare(events),
    )
    assert events == ["prepare", "commit", "dispatch"] * 2


async def test_submit_bulk_files_prepares_each_kit_before_its_dispatch(events) -> None:
    import uuid

    svc = KitService(_db(events))
    files = [
        {"kit_id": uuid.uuid4(), "filename": f"{n}.eml", "local_path": f"/tmp/{n}"}
        for n in ("a", "b")
    ]
    await svc.submit_bulk_files(files, prepare=_prepare(events))
    assert events == ["prepare", "commit", "dispatch"] * 2


async def test_create_from_url_prepares_before_commit_and_dispatch(events) -> None:
    async def prepare(investigation, kit) -> None:
        assert kit.investigation_id == investigation.id
        events.append("prepare")

    await InvestigationService(_db(events)).create_from_url(
        "https://lure.test/", prepare=prepare,
    )
    assert events == ["prepare", "commit", "dispatch"]


async def test_create_kit_route_links_investigation_before_dispatch(events) -> None:
    """End-to-end through the POST /kits handler: by the time the chain
    is dispatched, the kit already carries its investigation id."""
    from darla.api.kits import create_kit
    from darla.schemas.kit import KitCreate

    db = _db(events)
    added: list = []
    db.add.side_effect = added.append

    async def commit() -> None:
        kit = next(o for o in added if isinstance(o, Kit))
        events.append(f"commit(investigation={'set' if kit.investigation_id else 'NULL'})")

    db.commit = AsyncMock(side_effect=commit)

    await create_kit(KitCreate(url="https://lure.test/", force=True), db)
    assert events == ["commit(investigation=set)", "dispatch"]
