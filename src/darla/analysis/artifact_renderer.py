"""Artifact rendering — screenshots for EML, SVG, PDF, and DOCX files.

These artifacts never fire the live-URL browser_download_kit path, but analysts
still need to see what the recipient would have seen. This module produces
passive visual renders that land in the kit's ``_screenshots/`` directory so
the existing screenshot API surfaces them with no frontend changes.

Safety model: everything renders *offline*. EML and SVG go through Camoufox
with network blocked and JavaScript disabled — we're producing a visual
facsimile, not re-executing attacker content. PDF and DOCX never touch a
browser; they go through pymupdf (PDF) or LibreOffice headless (DOCX → PDF
→ pymupdf).
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# File extensions we know how to render.
EML_EXTS = frozenset({".eml"})
SVG_EXTS = frozenset({".svg"})
PDF_EXTS = frozenset({".pdf"})
DOCX_EXTS = frozenset({".docx", ".doc", ".rtf", ".odt"})

# Camoufox viewport for passive render (matches landing-page screenshot dims).
_VIEWPORT = {"width": 1280, "height": 1024}

# Caps to keep renders bounded.
_MAX_PDF_PAGES = 10
_MAX_INPUT_BYTES = 50 * 1024 * 1024  # 50 MB
_PDF_RENDER_DPI = 100
_DOCX_CONVERT_TIMEOUT = 60  # seconds

# Strip markup that would fetch remote content or execute script when we
# render an EML's HTML body. Passive visual render only — belt-and-suspenders
# alongside Camoufox network blocking and JS disable.
_STRIP_PATTERNS = (
    re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*script\b[^>]*/?\s*>", re.IGNORECASE),
    re.compile(r"<\s*iframe\b[^>]*>.*?<\s*/\s*iframe\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*iframe\b[^>]*/?\s*>", re.IGNORECASE),
    re.compile(r"<\s*object\b[^>]*>.*?<\s*/\s*object\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\s*embed\b[^>]*/?\s*>", re.IGNORECASE),
    # Inline event handlers (onload=, onclick=, ...).
    re.compile(r"""\s+on[a-z]+\s*=\s*(["'])[^"']*\1""", re.IGNORECASE),
    # javascript: URLs in href/src.
    re.compile(
        r"""(href|src)\s*=\s*(["'])\s*javascript:[^"']*\2""",
        re.IGNORECASE,
    ),
)


@dataclass
class RenderResult:
    """Output from a single artifact render."""

    rendered_files: list[str] = field(default_factory=list)
    stage_labels: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    format: str | None = None  # "eml", "svg", "pdf", "docx"


def _normalized_suffix(path: Path) -> str:
    """Return the real extension, tolerating attacker-appended trailing dots.

    Phishing attachments often arrive with names like ``ATT021.svg..`` where
    trailing dots/spaces make ``Path.suffix`` return ``"."``. We strip those
    and re-read the suffix so extension-based classification still works.
    """
    name = path.name.rstrip(". ")
    return Path(name).suffix.lower()


def classify_artifact(path: Path) -> str | None:
    """Return one of {eml, svg, pdf, docx} or None if unsupported."""
    ext = _normalized_suffix(path)
    if ext in EML_EXTS:
        return "eml"
    if ext in SVG_EXTS:
        return "svg"
    if ext in PDF_EXTS:
        return "pdf"
    if ext in DOCX_EXTS:
        return "docx"
    return None


def render_artifact(
    filepath: str | Path,
    screenshots_dir: str | Path,
    *,
    timeout: int = 30,
) -> RenderResult:
    """Dispatch to the right renderer based on file extension.

    All renderers are best-effort and never raise to the caller — errors
    land in the ``errors`` field of the result.
    """
    fpath = Path(filepath)
    out_dir = Path(screenshots_dir)

    result = RenderResult()
    result.format = classify_artifact(fpath)

    if result.format is None:
        result.errors.append(f"unsupported_extension:{fpath.suffix}")
        return result

    if not fpath.is_file():
        result.errors.append("file_not_found")
        return result

    size = fpath.stat().st_size
    if size > _MAX_INPUT_BYTES:
        result.errors.append(f"too_large:{size}")
        return result
    if size == 0:
        result.errors.append("empty_file")
        return result

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        if result.format == "eml":
            _render_eml(fpath, out_dir, result, timeout=timeout)
        elif result.format == "svg":
            _render_svg(fpath, out_dir, result, timeout=timeout)
        elif result.format == "pdf":
            _render_pdf(fpath, out_dir, result)
        elif result.format == "docx":
            _render_docx(fpath, out_dir, result)
    except Exception as e:
        logger.exception("Render failed for %s (%s)", fpath, result.format)
        result.errors.append(f"render_exception:{type(e).__name__}:{e}")

    return result


# ---------------------------------------------------------------------------
# EML
# ---------------------------------------------------------------------------

def _sanitize_email_html(body_html: str) -> str:
    """Remove script/iframe/object/embed and inline event handlers."""
    sanitized = body_html
    for pattern in _STRIP_PATTERNS:
        sanitized = pattern.sub("", sanitized)
    return sanitized


def _render_eml_body(eml_path: Path) -> tuple[str, dict[str, str]]:
    """Parse an EML and return (sanitized_html, headers) for rendering.

    If the EML has no HTML body, a stub is built from the text body or
    headers so we still produce something visual.
    """
    # Local import so EML parsing stays a best-effort extra rather than a
    # hard dep of the renderer module.
    from darla.analysis.eml_parser import EMLParser

    parsed = EMLParser().parse(str(eml_path))
    headers = parsed.headers or {}

    if parsed.body_html:
        return _sanitize_email_html(parsed.body_html), headers

    # Fallback: text body, escaped.
    if parsed.body_text:
        return (
            "<pre style='font-family:monospace;white-space:pre-wrap;"
            "padding:16px'>"
            + html.escape(parsed.body_text)
            + "</pre>"
        ), headers

    return "<p><em>(no body)</em></p>", headers


def _build_eml_preview_html(body_html: str, headers: dict[str, str]) -> str:
    """Wrap sanitized body in a header card so the screenshot shows From/Subject."""
    def h(name: str) -> str:
        return html.escape(headers.get(name, "") or "")

    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<style>
  body {{ margin:0; font-family:-apple-system,Segoe UI,sans-serif; color:#222; }}
  .envelope {{ padding:16px 24px; background:#f4f5f7; border-bottom:1px solid #ddd; }}
  .envelope .row {{ margin:2px 0; font-size:13px; }}
  .envelope .label {{ display:inline-block; width:70px; color:#666; }}
  .envelope .subject {{ font-size:18px; font-weight:600; margin-top:6px; }}
  .body {{ padding:16px 24px; }}
  img[src^='http'], img[src^='//'] {{ display:none !important; }}
</style>
</head><body>
<div class='envelope'>
  <div class='row'><span class='label'>From:</span>{h('From')}</div>
  <div class='row'><span class='label'>To:</span>{h('To')}</div>
  <div class='row'><span class='label'>Date:</span>{h('Date')}</div>
  <div class='subject'>{h('Subject')}</div>
</div>
<div class='body'>{body_html}</div>
</body></html>"""


def _render_eml(
    eml_path: Path, out_dir: Path, result: RenderResult, *, timeout: int
) -> None:
    try:
        body_html, headers = _render_eml_body(eml_path)
    except Exception as e:
        result.errors.append(f"eml_parse_error:{e}")
        return

    preview_html = _build_eml_preview_html(body_html, headers)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", encoding="utf-8", delete=False,
    ) as tmp:
        tmp.write(preview_html)
        tmp_path = Path(tmp.name)

    try:
        out_file = out_dir / "00_email.png"
        _camoufox_screenshot_file(
            tmp_path, out_file, timeout=timeout, disable_js=True,
        )
        result.rendered_files.append(str(out_file))
        result.stage_labels.append("Email")
    except Exception as e:
        result.errors.append(f"eml_render_error:{e}")
    finally:
        with contextlib.suppress(Exception):
            tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------

def _render_svg(
    svg_path: Path, out_dir: Path, result: RenderResult, *, timeout: int
) -> None:
    # Wrap SVG in a minimal HTML shell so Camoufox renders it as a page.
    try:
        svg_bytes = svg_path.read_bytes()
    except Exception as e:
        result.errors.append(f"svg_read_error:{e}")
        return

    svg_text = svg_bytes.decode("utf-8", errors="replace")
    preview = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<style>body{{margin:0;display:flex;justify-content:center;align-items:center;
min-height:100vh;background:#fff;}}svg{{max-width:100%;max-height:100vh;}}</style>
</head><body>{svg_text}</body></html>"""

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", encoding="utf-8", delete=False,
    ) as tmp:
        tmp.write(preview)
        tmp_path = Path(tmp.name)

    try:
        out_file = out_dir / "00_svg.png"
        _camoufox_screenshot_file(
            tmp_path, out_file, timeout=timeout, disable_js=True,
        )
        result.rendered_files.append(str(out_file))
        result.stage_labels.append("Svg")
    except Exception as e:
        result.errors.append(f"svg_render_error:{e}")
    finally:
        with contextlib.suppress(Exception):
            tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# PDF (pymupdf) and DOCX (LibreOffice → PDF → pymupdf)
# ---------------------------------------------------------------------------

def _render_pdf(pdf_path: Path, out_dir: Path, result: RenderResult) -> None:
    try:
        import pymupdf  # type: ignore[import-untyped]
    except ImportError:
        result.errors.append("pymupdf_not_installed")
        return

    try:
        doc = pymupdf.open(str(pdf_path))
    except Exception as e:
        result.errors.append(f"pdf_open_error:{e}")
        return

    try:
        page_count = min(len(doc), _MAX_PDF_PAGES)
        if page_count == 0:
            result.errors.append("pdf_no_pages")
            return

        # Use a DPI matrix for sharper output than the default 72 DPI.
        zoom = _PDF_RENDER_DPI / 72.0
        matrix = pymupdf.Matrix(zoom, zoom)

        for i in range(page_count):
            try:
                page = doc.load_page(i)
                pix = page.get_pixmap(matrix=matrix, alpha=False)
                out_file = out_dir / f"00_pdf_p{i + 1:02d}.png"
                pix.save(str(out_file))
                result.rendered_files.append(str(out_file))
                result.stage_labels.append(f"Pdf P{i + 1}")
            except Exception as e:
                result.errors.append(f"pdf_page_{i}_error:{e}")
    finally:
        doc.close()


def _render_docx(docx_path: Path, out_dir: Path, result: RenderResult) -> None:
    soffice = _find_soffice()
    if not soffice:
        result.errors.append("libreoffice_not_installed")
        return

    # LibreOffice writes output next to the input unless --outdir is set.
    with tempfile.TemporaryDirectory(prefix="docx_render_") as tmpdir:
        tmp = Path(tmpdir)
        try:
            proc = subprocess.run(
                [
                    soffice, "--headless", "--nologo", "--nofirststartwizard",
                    "--convert-to", "pdf", "--outdir", str(tmp), str(docx_path),
                ],
                capture_output=True, timeout=_DOCX_CONVERT_TIMEOUT, check=False,
            )
        except subprocess.TimeoutExpired:
            result.errors.append("docx_convert_timeout")
            return
        except Exception as e:
            result.errors.append(f"docx_convert_error:{e}")
            return

        if proc.returncode != 0:
            # LibreOffice sometimes prints to stderr but still succeeds.
            # Only fail if we didn't produce a PDF.
            pdfs = list(tmp.glob("*.pdf"))
            if not pdfs:
                stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
                result.errors.append(f"docx_convert_failed:{stderr}")
                return

        pdfs = list(tmp.glob("*.pdf"))
        if not pdfs:
            result.errors.append("docx_no_output_pdf")
            return

        # Render the converted PDF into screenshots.
        pdf_result = RenderResult()
        _render_pdf(pdfs[0], out_dir, pdf_result)

        # Relabel so it's clear the source was DOCX, not a native PDF.
        for i, (f, _) in enumerate(
            zip(pdf_result.rendered_files, pdf_result.stage_labels, strict=False)
        ):
            renamed = out_dir / f"00_docx_p{i + 1:02d}.png"
            try:
                Path(f).rename(renamed)
                result.rendered_files.append(str(renamed))
                result.stage_labels.append(f"Docx P{i + 1}")
            except Exception:
                result.rendered_files.append(f)
                result.stage_labels.append(f"Docx P{i + 1}")

        result.errors.extend(pdf_result.errors)


def _find_soffice() -> str | None:
    """Locate the LibreOffice binary on PATH."""
    for name in ("soffice", "libreoffice"):
        found = shutil.which(name)
        if found:
            return found
    return None


# ---------------------------------------------------------------------------
# Camoufox shared helper
# ---------------------------------------------------------------------------

def _camoufox_screenshot_file(
    html_file: Path,
    out_file: Path,
    *,
    timeout: int,
    disable_js: bool,
) -> None:
    """Open a local HTML file in Camoufox with network blocked and screenshot.

    Synchronous wrapper over the async path so Celery tasks can call it
    straight. Raises on fatal errors so the caller can record them.
    """
    asyncio.run(
        _async_camoufox_screenshot_file(
            html_file, out_file, timeout=timeout, disable_js=disable_js,
        )
    )


async def _async_camoufox_screenshot_file(
    html_file: Path,
    out_file: Path,
    *,
    timeout: int,
    disable_js: bool,
) -> None:
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError as e:
        raise RuntimeError("camoufox not installed") from e

    file_url = html_file.resolve().as_uri()

    async with AsyncCamoufox(
        headless="virtual",
        humanize=False,
        block_webrtc=True,
        disable_coop=True,
        i_know_what_im_doing=True,
    ) as browser:
        ctx_kwargs: dict = {
            "viewport": _VIEWPORT,
            "ignore_https_errors": True,
        }
        if disable_js:
            ctx_kwargs["java_script_enabled"] = False

        context = await browser.new_context(**ctx_kwargs)

        # Hard block all network except the local file we're rendering.
        async def _block_remote(route, request):
            if request.url.startswith("file://"):
                await route.continue_()
            else:
                await route.abort()

        await context.route("**/*", _block_remote)

        page = await context.new_page()
        page.set_default_timeout(timeout * 1000)
        page.set_default_navigation_timeout(timeout * 1000)

        # Even on navigation timeout, try to capture whatever painted.
        with contextlib.suppress(Exception):
            await page.goto(file_url, wait_until="domcontentloaded")

        # Brief settle so fonts/layout apply.
        with contextlib.suppress(Exception):
            await page.wait_for_timeout(500)

        await page.screenshot(path=str(out_file), full_page=True)
        await context.close()
