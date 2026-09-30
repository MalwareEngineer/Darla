"""Tests for stage comparison, flow alignment, and clustering."""

from darla.analysis.stage_compare import (
    align_flows,
    cluster_stages,
    compare_stages,
)


def _fp(**kw):
    base = {"role": "bot_check"}
    base.update(kw)
    return base


def test_compare_identical_script_set_is_same():
    a = _fp(script_shas=["s1", "s2", "s3"], skeleton_hash="k1",
            request_shape_hash="r1")
    b = _fp(script_shas=["s1", "s2", "s3"], skeleton_hash="k1",
            request_shape_hash="r1")
    cmp = compare_stages(a, b)
    assert cmp.verdict == "same"
    assert cmp.score >= 0.85


def test_compare_disjoint_scripts_different_layout_is_different():
    a = _fp(script_shas=["s1"], skeleton_hash="k1", request_shape_hash="r1")
    b = _fp(script_shas=["z9"], skeleton_hash="k2", request_shape_hash="r2")
    cmp = compare_stages(a, b)
    assert cmp.verdict == "different"


def test_compare_signal_breakdown_present():
    a = _fp(script_shas=["s1", "s2"], skeleton_hash="k1")
    b = _fp(script_shas=["s1"], skeleton_hash="k2")
    cmp = compare_stages(a, b)
    names = {s.name for s in cmp.signals}
    assert "script_set" in names
    assert "skeleton" in names
    d = cmp.to_dict()
    assert d["verdict"] in ("same", "similar", "different")
    assert isinstance(d["signals"], list)


def test_compare_cred_capture_uses_injected():
    a = _fp(role="cred_capture", injected_scripts=["harv1"],
            injected_endpoints=["evil.com/ws"], request_shape_hash="r1")
    b = _fp(role="cred_capture", injected_scripts=["harv1"],
            injected_endpoints=["evil.com/ws"], request_shape_hash="r1")
    cmp = compare_stages(a, b)
    assert cmp.verdict == "same"
    # Two Microsoft AiTM pages with the SAME proxied HTML but DIFFERENT
    # injected harvesters must read as different.
    c = _fp(role="cred_capture", injected_scripts=["harvOTHER"],
            injected_endpoints=["other.com/ws"], request_shape_hash="r2")
    cmp2 = compare_stages(a, c)
    assert cmp2.verdict != "same"


def test_align_flows_matches_shared_bot_check_diverges_at_aitm():
    flow_a = [
        _fp(role="bot_check", script_shas=["bc1"], skeleton_hash="bck"),
        _fp(role="cred_capture", injected_scripts=["hA"], request_shape_hash="rA"),
    ]
    flow_b = [
        _fp(role="bot_check", script_shas=["bc1"], skeleton_hash="bck"),
        _fp(role="cred_capture", injected_scripts=["hB"], request_shape_hash="rB"),
    ]
    pairs = align_flows(flow_a, flow_b)
    matches = [p for p in pairs if p.kind == "match"]
    assert len(matches) == 2
    bot = next(p for p in matches if p.role == "bot_check")
    cred = next(p for p in matches if p.role == "cred_capture")
    assert bot.comparison["verdict"] == "same"
    assert cred.comparison["verdict"] != "same"


def test_align_flows_insertion_when_one_flow_has_extra_stage():
    flow_a = [
        _fp(role="bot_check", script_shas=["bc1"], skeleton_hash="bck"),
        _fp(role="interstitial", skeleton_hash="int"),
        _fp(role="cred_capture", request_shape_hash="rA"),
    ]
    flow_b = [
        _fp(role="bot_check", script_shas=["bc1"], skeleton_hash="bck"),
        _fp(role="cred_capture", request_shape_hash="rA"),
    ]
    pairs = align_flows(flow_a, flow_b)
    only_a = [p for p in pairs if p.kind == "only_a"]
    assert len(only_a) == 1
    assert only_a[0].role == "interstitial"
    assert sum(1 for p in pairs if p.kind == "match") == 2


def test_cluster_stages_groups_similar():
    stages = [
        {"id": "1", "role": "bot_check", "script_shas": ["a", "b"],
         "skeleton_hash": "k", "request_shape_hash": "r"},
        {"id": "2", "role": "bot_check", "script_shas": ["a", "b"],
         "skeleton_hash": "k", "request_shape_hash": "r"},
        {"id": "3", "role": "bot_check", "script_shas": ["x"],
         "skeleton_hash": "z", "request_shape_hash": "q"},
        {"id": "4", "role": "cred_capture", "script_shas": ["a", "b"]},
    ]
    clusters = cluster_stages(stages, role="bot_check")
    # 1 and 2 cluster; 3 alone. cred_capture ignored.
    assert [sorted(c) for c in clusters] == [["1", "2"], ["3"]]


def test_cluster_stages_empty():
    assert cluster_stages([], role="bot_check") == []
