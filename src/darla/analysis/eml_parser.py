"""EML (email message) parser — extracts headers, body, links, attachments."""

import email
import email.policy
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

# Image MIME types we care about (for QR code scanning downstream)
IMAGE_TYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
})


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    data: bytes
    size: int


@dataclass
class EmbeddedImage:
    content_id: str | None
    content_type: str
    data: bytes
    filename: str | None


@dataclass
class NestedEML:
    """A message/rfc822 attachment — carried but not merged into the outer result.

    The task layer turns each of these into its own child kit so each EML in
    the chain gets independent analysis (IOC extraction per envelope,
    attachment handling per message, etc.).
    """

    filename: str
    subject: str | None
    data: bytes
    size: int


@dataclass
class EMLParseResult:
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str | None = None
    body_html: str | None = None
    links: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    embedded_images: list[EmbeddedImage] = field(default_factory=list)
    nested_emls: list[NestedEML] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class _LinkExtractor(HTMLParser):
    """Extract URLs from href, src, and form action attributes."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = dict(attrs)
        url = None
        if tag == "a":
            url = attr_dict.get("href")
        elif tag in ("img", "script", "iframe", "embed", "source", "video", "audio"):
            url = attr_dict.get("src")
        elif tag == "form":
            url = attr_dict.get("action")
        elif tag == "link":
            url = attr_dict.get("href")
        elif tag == "meta":
            # Handle meta refresh redirects
            content = attr_dict.get("content", "")
            if attr_dict.get("http-equiv", "").lower() == "refresh" and "url=" in content.lower():
                match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE)
                if match:
                    url = match.group(1)

        if url and url.startswith(("http://", "https://")):
            self.links.append(url)

    def error(self, message: str):
        pass  # Suppress HTMLParser errors


# Regex fallback for URLs in plain text
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


# Characters that are illegal in Windows filenames or break path operations.
# We also strip trailing dots/spaces — attackers append them to hide the real
# extension (e.g. "ATT021.svg.." so Path.suffix returns "." and extension-based
# classifiers miss the file).
_BAD_FILENAME_CHARS = re.compile(r'[\x00-\x1f<>:"/\\|?*]')


def _safe_attachment_name(name: str | None) -> str:
    """Normalize an attachment filename for on-disk storage.

    - Strips path components (basename only).
    - Strips control chars and Windows-reserved characters.
    - Strips trailing dots/spaces that break ``Path.suffix`` and are
      invalid on Windows.
    - Falls back to ``attachment`` if the result is empty.
    """
    if not name:
        return "attachment"
    # Basename only — never honor attacker-supplied path components.
    # Treat ``\`` as a separator on every platform: attackers send
    # Windows-style paths, and the workers run on Linux, where
    # ``Path(...).name`` keeps a backslash-separated directory part.
    base = PurePosixPath(name.replace("\\", "/")).name
    cleaned = _BAD_FILENAME_CHARS.sub("_", base).rstrip(". ")
    return cleaned or "attachment"


def _walk_skip_rfc822(msg):
    """Like msg.walk() but does not descend into message/rfc822 parts.

    We handle message/rfc822 via explicit recursion in parse_bytes(),
    so the default walk() would double-process inner parts.
    """
    yield msg
    # If this part IS message/rfc822, don't descend — children are
    # handled by recursive parse_bytes() call in the walk loop.
    if msg.get_content_type() == "message/rfc822":
        return
    if msg.is_multipart():
        for part in msg.get_payload():
            yield from _walk_skip_rfc822(part)


class EMLParser:
    """Parse .eml files to extract headers, body, links, attachments, and images."""

    def parse(self, filepath: str) -> EMLParseResult:
        """Parse an .eml file from disk."""
        try:
            with open(filepath, "rb") as f:
                return self.parse_bytes(f.read())
        except Exception as e:
            logger.exception("Failed to read EML file %s: %s", filepath, e)
            return EMLParseResult(errors=[f"read_error: {e}"])

    def parse_bytes(self, raw: bytes) -> EMLParseResult:
        """Parse raw email bytes."""
        result = EMLParseResult()
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception as e:
            result.errors.append(f"parse_error: {e}")
            return result

        # Extract headers
        for key in ("From", "To", "Subject", "Date", "Message-ID",
                     "Reply-To", "Return-Path", "X-Mailer", "X-Originating-IP",
                     "Received", "Content-Type", "DKIM-Signature"):
            val = msg.get(key)
            if val:
                result.headers[key] = str(val)

        # Extract all Received headers (can be multiple)
        received = msg.get_all("Received")
        if received:
            result.headers["Received-All"] = "\n".join(str(r) for r in received)

        # Walk MIME parts (skip into message/rfc822 — handled via recursion)
        for part in _walk_skip_rfc822(msg):
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Nested EML (message/rfc822) — carry the inner bytes up to the
            # task layer as a NestedEML and let it spawn a child kit.
            # We intentionally do NOT merge attachments/links/body into the
            # outer result: each EML in the chain is its own artifact.
            if content_type == "message/rfc822":
                inner_payloads = part.get_payload()
                if isinstance(inner_payloads, list):
                    for inner_msg in inner_payloads:
                        try:
                            # Re-emit with CRLF (wire-format) so the saved
                            # .eml can be re-parsed as an independent artifact
                            # by strict parsers.
                            from email.generator import BytesGenerator
                            from io import BytesIO
                            buf = BytesIO()
                            BytesGenerator(
                                buf,
                                policy=email.policy.default.clone(
                                    linesep="\r\n"
                                ),
                            ).flatten(inner_msg)
                            inner_bytes = buf.getvalue()
                            subj = inner_msg.get("Subject")
                            fname = part.get_filename()
                            if not fname:
                                safe_subj = (str(subj) if subj else "inner").replace("/", "_")
                                fname = safe_subj[:80] + ".eml"
                            result.nested_emls.append(NestedEML(
                                filename=fname,
                                subject=str(subj) if subj else None,
                                data=inner_bytes,
                                size=len(inner_bytes),
                            ))
                        except Exception as e:
                            result.errors.append(f"inner_eml_error: {e}")
                continue

            # Embedded images (inline with Content-ID)
            if content_type in IMAGE_TYPES:
                try:
                    data = part.get_payload(decode=True)
                    if data:
                        result.embedded_images.append(EmbeddedImage(
                            content_id=part.get("Content-ID"),
                            content_type=content_type,
                            data=data,
                            filename=part.get_filename(),
                        ))
                except Exception as e:
                    result.errors.append(f"image_decode_error: {e}")
                continue

            # Attachments (non-text parts with filenames or explicit attachment disposition)
            if "attachment" in disposition or (
                part.get_filename() and content_type not in ("text/plain", "text/html")
            ):
                try:
                    data = part.get_payload(decode=True)
                    if data:
                        fname = part.get_filename() or "attachment"
                        result.attachments.append(AttachmentInfo(
                            filename=fname,
                            content_type=content_type,
                            data=data,
                            size=len(data),
                        ))
                except Exception as e:
                    result.errors.append(f"attachment_decode_error: {e}")
                continue

            # Text bodies
            if content_type == "text/plain" and not result.body_text:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_text = payload.decode("utf-8", errors="replace")
                except Exception as e:
                    result.errors.append(f"text_decode_error: {e}")

            elif content_type == "text/html" and not result.body_html:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_html = payload.decode("utf-8", errors="replace")
                except Exception as e:
                    result.errors.append(f"html_decode_error: {e}")

        # Extract links from HTML body
        if result.body_html:
            result.links.extend(self._extract_links_from_html(result.body_html))

        # Extract links from plain text body
        if result.body_text:
            result.links.extend(self._extract_links_from_text(result.body_text))

        # Deduplicate links preserving order
        seen = set()
        deduped = []
        for link in result.links:
            if link not in seen:
                seen.add(link)
                deduped.append(link)
        result.links = deduped

        return result

    def _extract_links_from_html(self, html: str) -> list[str]:
        """Extract URLs from HTML using HTMLParser."""
        extractor = _LinkExtractor()
        try:
            extractor.feed(html)
        except Exception as e:
            logger.debug("HTML link extraction error: %s", e)
        return extractor.links

    def _extract_links_from_text(self, text: str) -> list[str]:
        """Extract URLs from plain text using regex."""
        return _URL_RE.findall(text)

    def save_attachments(self, result: EMLParseResult, output_dir: str) -> list[str]:
        """Save attachments and embedded images to disk. Returns saved file paths."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        saved = []

        for att in result.attachments:
            dest = out / _safe_attachment_name(att.filename)
            # Prevent path traversal
            if not dest.resolve().is_relative_to(out.resolve()):
                continue
            dest.write_bytes(att.data)
            saved.append(str(dest))

        for i, img in enumerate(result.embedded_images):
            ext = img.content_type.split("/")[-1] if "/" in img.content_type else "bin"
            fname = img.filename or f"embedded_{i}.{ext}"
            dest = out / _safe_attachment_name(fname)
            if not dest.resolve().is_relative_to(out.resolve()):
                continue
            dest.write_bytes(img.data)
            saved.append(str(dest))

        # Save HTML body to disk for downstream YARA/IOC/deobfuscation
        if result.body_html:
            html_dest = out / "body.html"
            html_dest.write_text(result.body_html, encoding="utf-8")
            saved.append(str(html_dest))

        return saved

    def save_nested_emls(
        self, result: EMLParseResult, output_dir: str,
    ) -> list[tuple["NestedEML", str]]:
        """Write nested EMLs to disk in their own subdir. Returns [(nested, path)]."""
        out = Path(output_dir) / "_nested_emls"
        out.mkdir(parents=True, exist_ok=True)
        saved: list[tuple[NestedEML, str]] = []

        for i, nested in enumerate(result.nested_emls):
            # Ensure unique, collision-free filenames and enforce .eml extension
            base = nested.filename or f"nested_{i}.eml"
            if not base.lower().endswith(".eml"):
                base = base + ".eml"
            dest = out / base
            if not dest.resolve().is_relative_to(out.resolve()):
                # Path traversal attempt — fall back to an ordinal name
                dest = out / f"nested_{i}.eml"
            if dest.exists():
                dest = out / f"nested_{i}_{dest.stem}.eml"
            dest.write_bytes(nested.data)
            saved.append((nested, str(dest)))

        return saved
