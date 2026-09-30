"""Tests for attack-flow segmentation and role classification."""

from darla.analysis import staging
from darla.analysis.staging import StageRole, build_stage_specs, classify_role


def test_classify_turnstile_is_bot_check():
    assert classify_role(
        seq=1, total=3, url="https://x.com", visible_text="",
        markers={"turnstile": True}, dwell_seconds=2.0, is_final=False,
    ) == StageRole.BOT_CHECK


def test_classify_password_field_is_cred_capture():
    assert classify_role(
        seq=2, total=3, url="https://login.evil.com", visible_text="sign in",
        markers={"password_field": True}, dwell_seconds=5.0, is_final=True,
    ) == StageRole.CRED_CAPTURE


def test_classify_decoy_host_wins_over_position():
    assert classify_role(
        seq=1, total=2, url="https://www.temu.com/deals", visible_text="shop",
        markers={}, dwell_seconds=5.0, is_final=True,
    ) == StageRole.DECOY


def test_classify_password_on_decoy_host_not_cred():
    # A password field on a known decoy host is not the phish.
    role = classify_role(
        seq=1, total=2, url="https://office.com/login", visible_text="",
        markers={"password_field": True}, dwell_seconds=5.0, is_final=True,
    )
    assert role == StageRole.DECOY


def test_classify_bot_text_marker():
    assert classify_role(
        seq=0, total=2, url="https://x.com",
        visible_text="Checking your browser before you continue. Ray ID: abc",
        markers={}, dwell_seconds=3.0, is_final=False,
    ) == StageRole.BOT_CHECK


def test_classify_interstitial_marker():
    assert classify_role(
        seq=1, total=3, url="https://x.com",
        visible_text="Preparing your secure session, please wait",
        markers={}, dwell_seconds=2.5, is_final=False,
    ) == StageRole.INTERSTITIAL


def test_classify_short_hop_is_redirector():
    assert classify_role(
        seq=1, total=3, url="https://t.co/abc", visible_text="",
        markers={}, dwell_seconds=0.3, is_final=False,
    ) == StageRole.REDIRECTOR


def test_classify_lure_first_stage():
    assert classify_role(
        seq=0, total=3, url="https://lure.com", visible_text="click here to view",
        markers={}, dwell_seconds=4.0, is_final=False,
    ) == StageRole.LURE


def test_classify_unknown_when_nothing_fires():
    assert classify_role(
        seq=0, total=1, url="https://x.com", visible_text="hello world",
        markers={}, dwell_seconds=4.0, is_final=True,
    ) == StageRole.UNKNOWN


def test_build_stage_specs_orders_and_computes_dwell():
    manifest = [
        {"seq": 1, "url": "https://x.com/gate", "started_ts": 3.0,
         "ended_ts": 5.5, "markers": {"turnstile": True},
         "body_file": "stage_01.html", "status_code": 200},
        {"seq": 0, "url": "https://x.com/", "started_ts": 0.0,
         "ended_ts": 3.0, "nav_method": "initial",
         "body_file": "stage_00.html", "visible_text": "click here"},
        {"seq": 2, "url": "https://login.x.com/", "started_ts": 5.5,
         "ended_ts": 9.0, "markers": {"password_field": True},
         "body_file": "stage_02.html"},
    ]
    specs = build_stage_specs(manifest, [], [])
    assert [s.seq for s in specs] == [0, 1, 2]
    assert specs[0].role == StageRole.LURE
    assert specs[1].role == StageRole.BOT_CHECK
    assert specs[1].dwell_seconds == 2.5
    assert specs[2].role == StageRole.CRED_CAPTURE


def test_attribute_resources_by_time_window():
    manifest = [
        {"seq": 0, "url": "https://x.com/", "started_ts": 0.0, "ended_ts": 3.0},
        {"seq": 1, "url": "https://x.com/gate", "started_ts": 3.0, "ended_ts": 6.0},
    ]
    resource_manifest = [
        {"filename": "_browser_resources/001_a.js", "url": "https://x.com/a.js",
         "timestamp": 1.0, "content_type": "application/javascript"},
        {"filename": "_browser_resources/002_b.js", "url": "https://x.com/b.js",
         "timestamp": 4.5, "content_type": "application/javascript"},
        {"filename": "page.html", "url": "https://x.com/gate", "role": "final"},
    ]
    specs = build_stage_specs(manifest, [], resource_manifest)
    s0 = next(s for s in specs if s.seq == 0)
    s1 = next(s for s in specs if s.seq == 1)
    assert [r["url"] for r in s0.resources] == ["https://x.com/a.js"]
    assert [r["url"] for r in s1.resources] == ["https://x.com/b.js"]
    # The "final" role body is not attributed as a sub-resource.
    assert all("page.html" not in (r["path"] or "") for s in specs for r in s.resources)


def test_attribute_resources_prefers_explicit_doc_seq():
    manifest = [
        {"seq": 0, "url": "https://x.com/", "started_ts": 0.0, "ended_ts": 3.0},
        {"seq": 1, "url": "https://x.com/gate", "started_ts": 3.0, "ended_ts": 6.0},
    ]
    network_log = [
        {"type": "response", "url": "https://x.com/late.js", "doc_seq": 0},
    ]
    resource_manifest = [
        # Timestamp says stage 1, but explicit doc_seq says stage 0 — trust it.
        {"filename": "_browser_resources/late.js", "url": "https://x.com/late.js",
         "timestamp": 5.0, "content_type": "application/javascript"},
    ]
    specs = build_stage_specs(manifest, network_log, resource_manifest)
    s0 = next(s for s in specs if s.seq == 0)
    assert [r["url"] for r in s0.resources] == ["https://x.com/late.js"]


def test_segment_render_no_manifest_returns_empty(tmp_path):
    assert staging.segment_render(tmp_path) == []
