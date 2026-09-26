"""Tests for js_fetcher extensions that handle SVG inputs and terminal URL classification."""

from darla.analysis.js_fetcher import (
    JS_DYNAMIC_URL_RE,
    SCANNABLE_EXTENSIONS,
    SCRIPT_SRC_RE,
    ExternalJSFetcher,
)

# ---- SCANNABLE_EXTENSIONS ------------------------------------------------


def test_svg_in_scannable_extensions():
    assert ".svg" in SCANNABLE_EXTENSIONS
    # Existing members still present
    assert ".html" in SCANNABLE_EXTENSIONS
    assert ".js" in SCANNABLE_EXTENSIONS


# ---- SCRIPT_SRC_RE: xlink:href / href / src ------------------------------


def test_script_src_re_matches_html_src():
    m = SCRIPT_SRC_RE.search(b'<script src="https://a.example/x.js"></script>'.decode())
    assert m
    assert m.group(1) == "https://a.example/x.js"


def test_script_src_re_matches_svg_xlink_href():
    m = SCRIPT_SRC_RE.search(
        '<script xlink:href="https://a.example/xlink.js"/>'
    )
    assert m
    assert m.group(1) == "https://a.example/xlink.js"


def test_script_src_re_matches_svg2_href():
    m = SCRIPT_SRC_RE.search('<script href="https://a.example/svg2.js"/>')
    assert m
    assert m.group(1) == "https://a.example/svg2.js"


def test_script_src_re_matches_namespaced_tag():
    m = SCRIPT_SRC_RE.search(
        '<svg:script xlink:href="https://a.example/ns.js"/>'
    )
    assert m


# ---- JS_DYNAMIC_URL_RE: fetch / XHR / importScripts etc. -----------------


def test_dynamic_url_re_matches_fetch():
    matches = list(JS_DYNAMIC_URL_RE.finditer('fetch("https://a.example/1.js")'))
    assert matches
    # The matching group is whichever alternation fired
    groups = [g for g in matches[0].groups() if g]
    assert any("https://a.example/1.js" in g for g in groups)


def test_dynamic_url_re_matches_xhr_open():
    matches = list(
        JS_DYNAMIC_URL_RE.finditer('xhr.open("GET", "https://a.example/x")')
    )
    assert matches
    groups = [g for g in matches[0].groups() if g]
    assert any("https://a.example/x" in g for g in groups)


def test_dynamic_url_re_matches_import_scripts():
    matches = list(
        JS_DYNAMIC_URL_RE.finditer('importScripts("https://a.example/w.js")')
    )
    assert matches


def test_dynamic_url_re_matches_location_assignment():
    matches = list(
        JS_DYNAMIC_URL_RE.finditer(
            'window.location.href = "https://a.example/landing"'
        )
    )
    assert matches
    groups = [g for g in matches[0].groups() if g]
    assert any("https://a.example/landing" in g for g in groups)


# ---- Terminal URL classifier ---------------------------------------------


def test_classify_js_extension_is_js():
    f = ExternalJSFetcher()
    assert f._classify_url("https://a.example/loader.js") == "js"
    assert f._classify_url("https://a.example/a.mjs") == "js"
    assert f._classify_url("https://a.example/a.json") == "js"


def test_classify_html_extension_is_terminal():
    f = ExternalJSFetcher()
    assert f._classify_url("https://a.example/login.html") == "terminal"
    assert f._classify_url("https://a.example/index.php") == "terminal"
    assert f._classify_url("https://a.example/form.aspx") == "terminal"


def test_classify_trailing_slash_is_terminal():
    f = ExternalJSFetcher()
    assert f._classify_url("https://a.example/login/") == "terminal"
    assert f._classify_url("https://a.example/") == "terminal"


def test_classify_extensionless_path_is_terminal():
    f = ExternalJSFetcher()
    # Device-code auth endpoints often look like this
    assert f._classify_url(
        "https://login.example.com/o/oauth2/deviceauth"
    ) == "terminal"


# ---- file:// base URL guard ----------------------------------------------


def test_file_base_url_rejects_relative_srcs():
    """EML-attached SVGs have a file:// base URL; relative refs must be dropped."""
    f = ExternalJSFetcher(source_url="file:///tmp/kit_xyz/attachment.svg")
    html = (
        '<script src="./evil.js"></script>'
        '<script src="https://a.example/ok.js"></script>'
    )
    urls = f._extract_script_urls(html, base_url=f._source_url)
    assert "https://a.example/ok.js" in urls
    # Relative URL must not have been joined with the file:// base
    assert not any(u.startswith("file://") for u in urls)


def test_http_base_url_still_joins_relative():
    f = ExternalJSFetcher(source_url="https://a.example/page.html")
    html = '<script src="/static/loader.js"></script>'
    urls = f._extract_script_urls(html, base_url=f._source_url)
    assert "https://a.example/static/loader.js" in urls
