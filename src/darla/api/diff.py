"""PhishDiff API endpoints — polymorphic kit comparison."""

import uuid

from fastapi import APIRouter, HTTPException, Query

from darla.api.deps import DbSession, Pagination
from darla.schemas.diff import (
    DiffablePair,
    DiffChangeCategory,
    DiffCompareRequest,
    DiffCompareResponse,
    DiffCompareSummary,
    DiffKitContent,
    DiffPairGroup,
    DiffPairGroupsResponse,
)
from darla.services.kit_service import KitService

router = APIRouter()


@router.get("/pairs", response_model=DiffPairGroupsResponse)
async def list_pair_groups(
    db: DbSession,
    pagination: Pagination,
    max_distance: int = Query(30, ge=1, le=200),
    max_size_ratio: float = Query(1.15, ge=1.0, le=5.0),
):
    """List domain groups containing ≥2 diffable kits."""
    svc = KitService(db)
    groups, total = await svc.get_diffable_pair_groups(
        offset=pagination.offset,
        limit=pagination.limit,
        max_distance=max_distance,
        max_size_ratio=max_size_ratio,
    )
    return DiffPairGroupsResponse(
        groups=[DiffPairGroup(**g) for g in groups],
        total=total,
    )


@router.get("/pairs/{kit_id}", response_model=list[DiffablePair])
async def get_diffable_pairs(
    kit_id: uuid.UUID,
    db: DbSession,
    max_distance: int = Query(30, ge=1, le=200),
    max_size_ratio: float = Query(1.15, ge=1.0, le=5.0),
):
    """Find diffable partners for a specific kit."""
    svc = KitService(db)
    pairs = await svc.find_diffable_pairs(
        kit_id, max_distance=max_distance, max_size_ratio=max_size_ratio,
    )
    return [DiffablePair(**p) for p in pairs]


@router.post("/compare", response_model=DiffCompareResponse)
async def compare_kits(body: DiffCompareRequest, db: DbSession):
    """Compare two kits: returns HTML content + structured diff summary."""

    from darla.analysis.hasher import compute_tlsh_distance
    from darla.analysis.polymorphism import (
        compute_structural_diff,
        normalize_html,
    )

    svc = KitService(db)

    html_a = await svc.get_kit_primary_html(body.kit_a_id)
    html_b = await svc.get_kit_primary_html(body.kit_b_id)
    if html_a is None or html_b is None:
        missing = []
        if html_a is None:
            missing.append(str(body.kit_a_id))
        if html_b is None:
            missing.append(str(body.kit_b_id))
        raise HTTPException(
            status_code=404,
            detail=f"No HTML content found for kit(s): {', '.join(missing)}",
        )

    kit_a = await svc.get_kit(body.kit_a_id)
    kit_b = await svc.get_kit(body.kit_b_id)

    # Compute TLSH distance
    tlsh_distance = None
    if kit_a and kit_b and kit_a.tlsh and kit_b.tlsh:
        tlsh_distance = compute_tlsh_distance(kit_a.tlsh, kit_b.tlsh)

    # Structural diff via polymorphism module
    diff = compute_structural_diff([
        (str(body.kit_a_id), html_a),
        (str(body.kit_b_id), html_b),
    ])

    # Beautify for readable diffs, then optionally normalize
    pretty_a = _beautify_html(html_a)
    pretty_b = _beautify_html(html_b)

    content_a = normalize_html(pretty_a) if body.normalize else pretty_a
    content_b = normalize_html(pretty_b) if body.normalize else pretty_b

    change_categories = _classify_changes(pretty_a, pretty_b)

    return DiffCompareResponse(
        kit_a=DiffKitContent(
            id=body.kit_a_id,
            source_url=kit_a.source_url if kit_a else "",
            content=content_a,
            file_size=kit_a.file_size if kit_a else None,
        ),
        kit_b=DiffKitContent(
            id=body.kit_b_id,
            source_url=kit_b.source_url if kit_b else "",
            content=content_b,
            file_size=kit_b.file_size if kit_b else None,
        ),
        summary=DiffCompareSummary(
            structural_similarity=diff.structural_similarity,
            tlsh_distance=tlsh_distance,
            change_categories=change_categories,
        ),
        normalized=body.normalize,
    )


_VOID_ELEMENTS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
})
_INLINE_ELEMENTS = frozenset({
    "a", "abbr", "b", "bdi", "bdo", "cite", "code", "em", "i",
    "kbd", "mark", "q", "s", "samp", "small", "span", "strong",
    "sub", "sup", "time", "u", "var",
})


def _beautify_html(html: str) -> str:
    """Pretty-print HTML so each tag gets its own line for readable diffs."""
    from html.parser import HTMLParser

    lines: list[str] = []
    indent = 0

    class Formatter(HTMLParser):
        nonlocal indent

        def handle_decl(self, decl: str) -> None:
            lines.append(f"{'  ' * indent}<!{decl}>")

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            nonlocal indent
            attr_str = ""
            if attrs:
                parts = []
                for k, v in attrs:
                    if v is None:
                        parts.append(k)
                    else:
                        parts.append(f'{k}="{v}"')
                attr_str = " " + " ".join(parts)
            if tag in _VOID_ELEMENTS or tag in _INLINE_ELEMENTS:
                lines.append(f"{'  ' * indent}<{tag}{attr_str}>")
            else:
                lines.append(f"{'  ' * indent}<{tag}{attr_str}>")
                indent += 1

        def handle_endtag(self, tag: str) -> None:
            nonlocal indent
            if tag not in _VOID_ELEMENTS and tag not in _INLINE_ELEMENTS:
                indent = max(0, indent - 1)
            lines.append(f"{'  ' * indent}</{tag}>")

        def handle_data(self, data: str) -> None:
            text = data.strip()
            if text:
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped:
                        lines.append(f"{'  ' * indent}{stripped}")

        def handle_comment(self, data: str) -> None:
            lines.append(f"{'  ' * indent}<!--{data}-->")

    parser = Formatter()
    parser.feed(html)
    return "\n".join(lines)


def _classify_changes(html_a: str, html_b: str) -> list[DiffChangeCategory]:
    """Categorize differences between two HTML strings."""
    import difflib
    import re

    lines_a = html_a.splitlines(keepends=True)
    lines_b = html_b.splitlines(keepends=True)

    categories: dict[str, list[str]] = {
        "CSS class names": [],
        "Title/heading text": [],
        "Token URLs": [],
        "Form element IDs": [],
        "Other": [],
    }

    css_class_re = re.compile(r'class\s*=\s*["\']', re.I)
    title_re = re.compile(r"<(title|h[1-6])\b", re.I)
    url_re = re.compile(r'(href|src|action)\s*=\s*["\']', re.I)
    id_re = re.compile(r'(id|name)\s*=\s*["\']', re.I)

    differ = difflib.unified_diff(lines_a, lines_b, n=0)
    for line in differ:
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            continue
        content = line[1:]
        example = content.strip()[:120]
        if not example:
            continue

        if css_class_re.search(content):
            cat = "CSS class names"
        elif title_re.search(content):
            cat = "Title/heading text"
        elif url_re.search(content):
            cat = "Token URLs"
        elif id_re.search(content):
            cat = "Form element IDs"
        else:
            cat = "Other"

        if len(categories[cat]) < 5:  # Cap examples
            categories[cat].append(example)

    return [
        DiffChangeCategory(category=cat, count=len(examples), examples=examples)
        for cat, examples in categories.items()
        if examples
    ]
