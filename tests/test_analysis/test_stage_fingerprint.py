"""Tests for stage fingerprinting primitives."""

from darla.analysis import stage_fingerprint as sf


def test_tag_skeleton_ignores_attrs_and_text():
    a = '<html><body><div class="x_1"><form id="f">hi</form></div></body></html>'
    b = '<html><body><div class="y_999"><form id="g">bye</form></div></body></html>'
    assert sf.tag_skeleton(a) == sf.tag_skeleton(b)
    assert sf.skeleton_hash(a) == sf.skeleton_hash(b)


def test_skeleton_hash_differs_on_structure():
    a = "<html><body><div></div></body></html>"
    b = "<html><body><div><span></span></div></body></html>"
    assert sf.skeleton_hash(a) != sf.skeleton_hash(b)


def test_skeleton_hash_empty():
    assert sf.skeleton_hash("") is None


def test_skeleton_similarity():
    a = ["html", "html>body", "html>body>div"]
    assert sf.skeleton_similarity(a, a) == 1.0
    assert sf.skeleton_similarity(a, []) == 0.0
    assert sf.skeleton_similarity([], []) == 1.0


def test_jaccard():
    assert sf.jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert sf.jaccard({"a"}, {"b"}) == 0.0
    assert sf.jaccard(set(), set()) == 1.0
    assert sf.jaccard({"a", "b"}, {"b", "c"}) == 1 / 3


def test_path_template_tokenizes():
    assert sf.path_template("https://a.com/api/9f3b2c8811/login?x=1") == "a.com/api/{t}/login"
    assert sf.path_template("https://a.com/u/12345") == "a.com/u/{t}"
    uuid_url = "https://a.com/s/1b4e28ba-2fa1-11d2-883f-0016d3cca427/next"
    assert sf.path_template(uuid_url) == "a.com/s/{t}/next"


def test_request_shape_collapses_and_filters():
    log = [
        {"type": "request", "method": "GET", "resource_type": "document",
         "url": "https://a.com/login"},
        {"type": "request", "method": "GET", "resource_type": "image",
         "url": "https://a.com/logo.png"},
        {"type": "request", "method": "POST", "resource_type": "xhr",
         "url": "https://a.com/api/9f3b/auth"},
        {"type": "request", "method": "POST", "resource_type": "xhr",
         "url": "https://a.com/api/aa11/auth"},  # collapses with prev
        {"type": "response", "url": "https://a.com/login"},
    ]
    shape = sf.request_shape(log)
    assert shape == ["GET a.com/login", "POST a.com/api/{t}/auth"]
    assert sf.request_shape_hash(log) is not None


def test_request_shape_empty():
    assert sf.request_shape([]) == []
    assert sf.request_shape_hash([]) is None


def test_phash_distance_identical_and_missing():
    assert sf.phash_distance("ffff0000ffff0000", "ffff0000ffff0000") == 0
    assert sf.phash_distance("0000000000000000", "0000000000000001") == 1
    assert sf.phash_distance(None, "x") is None


def test_detect_idp_baseline_microsoft():
    html = (
        "<html><head><title>Sign in</title></head><body>"
        "form action=login.microsoftonline.com convergedLogin lightbox-cover"
        "</body></html>"
    )
    assert sf.detect_idp_baseline(html) == "microsoft"


def test_detect_idp_baseline_needs_two_markers():
    # Single stray marker shouldn't classify.
    assert sf.detect_idp_baseline("just mentions google.com once") is None


def test_injected_fingerprint_subtracts_baseline():
    out = sf.injected_fingerprint(
        stage_script_shas={"aaa", "bbb", "ccc"},
        baseline_script_shas={"aaa", "bbb"},
        stage_endpoints={"a.com/api/{t}", "evil.com/ws"},
        baseline_endpoints={"a.com/api/{t}"},
    )
    assert out["injected_scripts"] == ["ccc"]
    assert out["injected_endpoints"] == ["evil.com/ws"]
    assert out["injected_hash"] is not None


def test_injected_fingerprint_nothing_injected():
    out = sf.injected_fingerprint({"a"}, {"a"}, {"x"}, {"x"})
    assert out["injected_scripts"] == []
    assert out["injected_hash"] is None


def test_extract_endpoints_from_log_and_text():
    log = [
        {"type": "request", "resource_type": "websocket",
         "url": "wss://evil.com/relay/abcdef123456"},
        {"type": "request", "resource_type": "xhr",
         "url": "https://evil.com/collect?v=1"},
    ]
    eps = sf.extract_endpoints(log, extra_text="new WebSocket('wss://c2.net/x')")
    assert "evil.com/relay/{t}" in eps
    assert "evil.com/collect" in eps
    assert "c2.net/x" in eps


def test_tlsh_bucket_short_hash():
    assert sf.tlsh_bucket(None) is None
    assert sf.tlsh_bucket("abc") is None
