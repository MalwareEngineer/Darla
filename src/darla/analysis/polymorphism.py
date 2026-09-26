"""Polymorphic phishing kit detection.

Identifies kits that serve structurally similar but token-randomized content
across renders (same relay domain, different TLSH hashes).  Produces a
structural diff highlighting constant elements (stable detection targets) vs
variable elements (evasion mechanisms).

Uses only stdlib ``html.parser`` — no new dependencies.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

logger = logging.getLogger(__name__)

# Regex patterns for values that are commonly randomized per-render
_DYNAMIC_VALUE_PATTERNS = [
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),  # UUID
    re.compile(r"[0-9a-f]{32,}", re.I),  # long hex tokens
    re.compile(r"\d{10,13}"),  # epoch timestamps
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # base64 blobs
]


@dataclass
class StructuralDiff:
    """Result of comparing HTML variants for polymorphic content."""

    constant_elements: list[str]
    variable_elements: list[str]
    constant_form_fields: list[str]
    variable_form_fields: list[str]
    token_patterns: list[str]
    structural_similarity: float  # 0.0–1.0
    variant_count: int


@dataclass
class PolymorphismResult:
    """Full polymorphism analysis for a group of sibling kits."""

    is_polymorphic: bool
    relay_domain: str
    variant_count: int
    structural_diff: StructuralDiff | None
    confidence: float  # 0.0–1.0
    sibling_kit_ids: list[str]


# ---------------------------------------------------------------------------
# HTML normalisation
# ---------------------------------------------------------------------------

@dataclass
class _Element:
    """Lightweight representation of an HTML element."""

    tag_path: str  # e.g. "html>body>div>form"
    tag: str
    attrs: dict[str, str]
    text_hash: str  # SHA-256 of direct text content


class _TreeParser(HTMLParser):
    """Parse HTML into a flat list of :class:`_Element` tuples."""

    def __init__(self) -> None:
        super().__init__()
        self._stack: list[str] = []
        self._elements: list[_Element] = []
        self._current_text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._flush_text()
        self._stack.append(tag)
        path = ">".join(self._stack)
        attr_dict = {}
        for k, v in attrs:
            # Normalise dynamic-looking values to a placeholder so they
            # don't pollute the structural comparison.
            if v and any(p.fullmatch(v) for p in _DYNAMIC_VALUE_PATTERNS):
                v = "__VAR__"
            attr_dict[k] = v or ""
        self._elements.append(_Element(
            tag_path=path,
            tag=tag,
            attrs=attr_dict,
            text_hash="",
        ))

    def handle_endtag(self, tag: str) -> None:
        self._flush_text()
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        self._current_text += data

    def _flush_text(self) -> None:
        text = self._current_text.strip()
        self._current_text = ""
        if text and self._elements:
            self._elements[-1].text_hash = hashlib.sha256(
                text.encode("utf-8", errors="replace")
            ).hexdigest()[:16]

    @property
    def elements(self) -> list[_Element]:
        self._flush_text()
        return self._elements


def _parse_html(html: str) -> list[_Element]:
    """Parse HTML string into normalised element list."""
    parser = _TreeParser()
    with contextlib.suppress(Exception):
        parser.feed(html)
    return parser.elements


# ---------------------------------------------------------------------------
# Structural diff
# ---------------------------------------------------------------------------

def compute_structural_diff(
    html_contents: list[tuple[str, str]],
) -> StructuralDiff:
    """Compare multiple HTML documents to find constant vs variable parts.

    *html_contents* is a list of ``(kit_id, html_string)`` pairs.
    """
    if not html_contents:
        return StructuralDiff(
            constant_elements=[], variable_elements=[],
            constant_form_fields=[], variable_form_fields=[],
            token_patterns=[], structural_similarity=0.0,
            variant_count=0,
        )

    all_parsed = [(kid, _parse_html(html)) for kid, html in html_contents]

    # Build a set of tag_paths per variant
    path_sets: list[set[str]] = []
    for _kid, elements in all_parsed:
        path_sets.append({e.tag_path for e in elements})

    # Constant = present in ALL variants; variable = present in some
    all_paths = set.union(*path_sets) if path_sets else set()
    constant_paths = set.intersection(*path_sets) if path_sets else set()
    variable_paths = all_paths - constant_paths

    # For constant paths, check which have stable text content across variants
    # and which have variable text (token randomisation)
    path_text_map: dict[str, set[str]] = {}
    for _kid, elements in all_parsed:
        for e in elements:
            if e.tag_path in constant_paths and e.text_hash:
                path_text_map.setdefault(e.tag_path, set()).add(e.text_hash)

    variable_text_paths = {
        path for path, hashes in path_text_map.items() if len(hashes) > 1
    }

    # Form field analysis — compare input/select/textarea elements
    form_field_sets: list[set[str]] = []
    for _kid, elements in all_parsed:
        fields = set()
        for e in elements:
            if e.tag in ("input", "select", "textarea"):
                name = e.attrs.get("name", "")
                typ = e.attrs.get("type", "")
                fields.add(f"{e.tag}[name={name},type={typ}]")
        form_field_sets.append(fields)

    all_fields = set.union(*form_field_sets) if form_field_sets else set()
    constant_fields = set.intersection(*form_field_sets) if form_field_sets else set()
    variable_fields = all_fields - constant_fields

    # Extract token patterns from variable text content
    token_patterns: set[str] = set()
    for _kid, html in html_contents:
        for pat in _DYNAMIC_VALUE_PATTERNS:
            if pat.search(html):
                token_patterns.add(pat.pattern)

    total = len(all_paths) if all_paths else 1
    similarity = len(constant_paths) / total

    return StructuralDiff(
        constant_elements=sorted(constant_paths - variable_text_paths),
        variable_elements=sorted(variable_paths | variable_text_paths),
        constant_form_fields=sorted(constant_fields),
        variable_form_fields=sorted(variable_fields),
        token_patterns=sorted(token_patterns),
        structural_similarity=round(similarity, 3),
        variant_count=len(html_contents),
    )


# ---------------------------------------------------------------------------
# Top-level detection
# ---------------------------------------------------------------------------

_CSS_CLASS_PATTERN = re.compile(r"([a-z]_[a-z]+_)\d{2,4}")


_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _decode_base64_blob(match: re.Match) -> str:
    """Try to decode a base64 match to readable text; leave unchanged if not decodable."""
    blob = match.group(0)
    try:
        raw = base64.b64decode(blob)
        text = raw.decode("utf-8", errors="ignore")
        # Only accept if the decoded content is substantially printable text
        stripped = text.replace("\n", "").replace("\r", "").replace("\t", "")
        if len(stripped) > 10 and stripped.isprintable():
            return text
    except Exception:
        pass
    # Not decodable to readable text — leave the original base64 as-is
    return blob


def normalize_html(html: str) -> str:
    """Decode and deobfuscate HTML for readable diffing.

    - Normalises CSS class suffixes (``a_widget_696`` → ``a_CLASS``)
    - Decodes base64-encoded blobs inline to reveal obfuscated payloads

    Does NOT replace values with ``__VAR__`` placeholders — the purpose
    of PhishDiff is to show what is the same and what is different, so
    real values must remain visible.
    """
    # CSS class-name randomisation (e.g. a_widget_696 → a_CLASS)
    out = _CSS_CLASS_PATTERN.sub(r"\g<1>CLASS", html)
    # Decode base64 blobs to reveal obfuscated content
    out = _BASE64_BLOB_RE.sub(_decode_base64_blob, out)
    return out


def detect_variants(
    siblings: list[tuple[str, str | None, str | None, Path | None]],
    dedup_threshold: int = 30,
    max_distance: int = 200,
    min_variants: int = 2,
) -> PolymorphismResult | None:
    """Detect polymorphism among sibling kits sharing a relay domain.

    *siblings* is a list of ``(kit_id, tlsh, source_url, local_path)`` tuples.

    Returns ``None`` if the group is too small, content is identical
    (dedup range), or kits are unrelated (above *max_distance*).
    """
    from darla.analysis.hasher import compute_tlsh_distance

    if len(siblings) < min_variants:
        return None

    # Group by relay domain
    domain_groups: dict[str, list[tuple[str, str | None, Path | None]]] = {}
    for kit_id, tlsh, source_url, local_path in siblings:
        from urllib.parse import urlparse
        domain = urlparse(source_url).hostname if source_url else None
        if domain:
            domain_groups.setdefault(domain, []).append((kit_id, tlsh, local_path))

    for domain, group in domain_groups.items():
        if len(group) < min_variants:
            continue

        # Check TLSH distances are in the polymorphism range
        # (above dedup threshold but below unrelatedness ceiling)
        has_polymorphic_pair = False
        for i, (_kid_a, tlsh_a, _) in enumerate(group):
            for _kid_b, tlsh_b, _ in group[i + 1:]:
                if not tlsh_a or not tlsh_b:
                    continue
                dist = compute_tlsh_distance(tlsh_a, tlsh_b)
                if dist is not None and dedup_threshold < dist <= max_distance:
                    has_polymorphic_pair = True
                    break
            if has_polymorphic_pair:
                break

        if not has_polymorphic_pair:
            continue

        # Read HTML content for structural diff
        html_contents: list[tuple[str, str]] = []
        for kit_id, _, local_path in group:
            if not local_path or not local_path.is_file():
                continue
            try:
                html = local_path.read_text(encoding="utf-8", errors="replace")
                html_contents.append((kit_id, html))
            except OSError:
                continue

        structural_diff = None
        confidence = 0.0
        if len(html_contents) >= min_variants:
            structural_diff = compute_structural_diff(html_contents)
            # Confidence: high structural similarity + variable tokens = confident polymorphism
            confidence = structural_diff.structural_similarity * 0.7
            if structural_diff.token_patterns:
                confidence += 0.2
            if structural_diff.variable_form_fields:
                confidence += 0.1
            confidence = round(min(confidence, 1.0), 3)

        return PolymorphismResult(
            is_polymorphic=True,
            relay_domain=domain,
            variant_count=len(group),
            structural_diff=structural_diff,
            confidence=confidence,
            sibling_kit_ids=[kid for kid, _, _ in group],
        )

    return None
