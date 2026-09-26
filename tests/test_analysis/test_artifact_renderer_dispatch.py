"""artifact_renderer dispatch / classification tests.

The heavy rendering paths (Camoufox, LibreOffice, pymupdf) require external
binaries and are covered by integration tests in CI. Here we verify the
pure-Python dispatch logic: file classification, size/empty guards, and
error paths that must never raise.
"""

from pathlib import Path

from darla.analysis.artifact_renderer import (
    _MAX_INPUT_BYTES,
    DOCX_EXTS,
    EML_EXTS,
    PDF_EXTS,
    SVG_EXTS,
    _sanitize_email_html,
    classify_artifact,
    render_artifact,
)

# ---- classify_artifact ---------------------------------------------------


def test_classify_eml():
    assert classify_artifact(Path("x.eml")) == "eml"
    assert classify_artifact(Path("X.EML")) == "eml"


def test_classify_svg():
    assert classify_artifact(Path("logo.svg")) == "svg"


def test_classify_pdf():
    assert classify_artifact(Path("doc.pdf")) == "pdf"


def test_classify_docx_family():
    for ext in DOCX_EXTS:
        assert classify_artifact(Path(f"doc{ext}")) == "docx"


def test_classify_tolerates_trailing_dots():
    """Phishing attachments often arrive as "name.svg.." — must still classify."""
    assert classify_artifact(Path("ATT021.svg..")) == "svg"
    assert classify_artifact(Path("file.pdf.")) == "pdf"
    assert classify_artifact(Path("MSG.eml. ")) == "eml"


def test_classify_unsupported_returns_none():
    assert classify_artifact(Path("page.html")) is None
    assert classify_artifact(Path("script.js")) is None
    assert classify_artifact(Path("archive.zip")) is None


def test_extension_sets_are_disjoint():
    """A single extension must classify to exactly one format."""
    all_sets = [EML_EXTS, SVG_EXTS, PDF_EXTS, DOCX_EXTS]
    flat = [ext for s in all_sets for ext in s]
    assert len(flat) == len(set(flat))


# ---- render_artifact guards (never raise) --------------------------------


def test_render_nonexistent_file(tmp_path: Path):
    out = tmp_path / "_screenshots"
    r = render_artifact(tmp_path / "missing.svg", out)
    assert r.rendered_files == []
    assert "file_not_found" in r.errors


def test_render_unsupported_extension(tmp_path: Path):
    target = tmp_path / "x.txt"
    target.write_text("hello")
    out = tmp_path / "_screenshots"
    r = render_artifact(target, out)
    assert r.rendered_files == []
    assert any(e.startswith("unsupported_extension:") for e in r.errors)


def test_render_empty_file(tmp_path: Path):
    target = tmp_path / "empty.svg"
    target.write_bytes(b"")
    out = tmp_path / "_screenshots"
    r = render_artifact(target, out)
    assert r.rendered_files == []
    assert "empty_file" in r.errors


def test_render_oversized_file(tmp_path: Path):
    target = tmp_path / "huge.pdf"
    target.write_bytes(b"%PDF-" + b"\0" * (_MAX_INPUT_BYTES + 1))
    out = tmp_path / "_screenshots"
    r = render_artifact(target, out)
    assert r.rendered_files == []
    assert any(e.startswith("too_large:") for e in r.errors)


# ---- EML HTML sanitization ----------------------------------------------


def test_sanitize_strips_script_tags():
    html = "<p>ok</p><script>alert(1)</script><p>more</p>"
    out = _sanitize_email_html(html)
    assert "<script>" not in out.lower()
    assert "alert(1)" not in out
    assert "<p>ok</p>" in out


def test_sanitize_strips_iframe():
    html = '<iframe src="https://evil.example"></iframe>'
    out = _sanitize_email_html(html)
    assert "<iframe" not in out.lower()


def test_sanitize_strips_inline_event_handlers():
    html = '<a href="https://ok.example" onclick="alert(1)">click</a>'
    out = _sanitize_email_html(html)
    assert "onclick" not in out.lower()
    assert "alert" not in out
    # The anchor tag itself survives
    assert "<a" in out
    assert "https://ok.example" in out


def test_sanitize_strips_javascript_href():
    html = '<a href="javascript:evil()">click</a>'
    out = _sanitize_email_html(html)
    assert "javascript:" not in out.lower()


def test_sanitize_leaves_benign_html_intact():
    html = "<h1>Hi</h1><p>Your package is on the way.</p><b>Bold</b>"
    out = _sanitize_email_html(html)
    assert "<h1>Hi</h1>" in out
    assert "package" in out


def test_sanitize_strips_object_and_embed():
    html = '<object data="evil.swf"></object><embed src="evil.swf"/>'
    out = _sanitize_email_html(html)
    assert "<object" not in out.lower()
    assert "<embed" not in out.lower()
