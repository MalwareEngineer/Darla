"""Screenshot-to-stage mapping in _assemble_stages_manifest.

A screenshot is tagged with the doc_seq that was on screen when it was
taken; the manifest must attach each shot to that stage, prefer a blank
landing capture over a post-interaction one, and still guarantee the
first/last stages carry a shot.
"""

from darla.analysis.browser_downloader import _assemble_stages_manifest


def _navs():
    return [
        {"seq": 0, "url": "https://x.com/", "started_ts": 0.0},
        {"seq": 1, "url": "https://x.com/gate", "started_ts": 3.0},
        {"seq": 2, "url": "https://login.x.com/", "started_ts": 6.0},
    ]


def _responses():
    return [
        {"url": "https://x.com/", "status": 200, "content_type": "text/html",
         "body": "<html><body>landing</body></html>", "index": 1, "timestamp": 0.5},
        {"url": "https://x.com/gate", "status": 200, "content_type": "text/html",
         "body": "<html><body>enter the email</body></html>", "index": 2, "timestamp": 3.5},
    ]


def test_screenshots_map_to_tagged_stage():
    log = [
        {"seq": 0, "file": "_screenshots/01_landing.png", "blank": False},
        {"seq": 1, "file": "_screenshots/02c_lure_cta.png", "blank": False},
        {"seq": 2, "file": "_screenshots/03_phish.png", "blank": False},
    ]
    manifest, _ = _assemble_stages_manifest(
        _navs(), _responses(), "https://login.x.com/",
        "<html><body>login</body></html>", "login", log,
    )
    by_seq = {m["seq"]: m for m in manifest}
    assert by_seq[0]["screenshot_file"] == "_screenshots/01_landing.png"
    assert by_seq[1]["screenshot_file"] == "_screenshots/02c_lure_cta.png"
    assert by_seq[2]["screenshot_file"] == "_screenshots/03_phish.png"


def test_blank_capture_preferred_for_stage():
    # Same stage has both a blank landing shot and a post-fill shot;
    # the blank one wins so the flow shows what the victim first saw.
    log = [
        {"seq": 1, "file": "_screenshots/02c_lure_cta.png", "blank": False},
        {"seq": 1, "file": "_screenshots/01_email_blank.png", "blank": True},
    ]
    manifest, _ = _assemble_stages_manifest(
        _navs(), _responses(), "https://login.x.com/", "x", "x", log,
    )
    by_seq = {m["seq"]: m for m in manifest}
    assert by_seq[1]["screenshot_file"] == "_screenshots/01_email_blank.png"


def test_falls_back_to_heuristic_without_log():
    manifest, _ = _assemble_stages_manifest(
        _navs(), _responses(), "https://login.x.com/", "x", "x", None,
    )
    assert manifest[0]["screenshot_file"] == "_screenshots/01_landing.png"
    assert manifest[-1]["screenshot_file"] == "_screenshots/03_phish.png"


def test_terminal_stage_always_has_a_shot():
    # Only an intermediate stage was captured; terminal still gets 03_phish.
    log = [{"seq": 1, "file": "_screenshots/02c_lure_cta.png", "blank": False}]
    manifest, _ = _assemble_stages_manifest(
        _navs(), _responses(), "https://login.x.com/", "x", "x", log,
    )
    assert manifest[-1]["screenshot_file"] == "_screenshots/03_phish.png"
    assert manifest[1]["screenshot_file"] == "_screenshots/02c_lure_cta.png"
