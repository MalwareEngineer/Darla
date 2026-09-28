"""HTTP redirect chain tracker for investigation-mode downloads.

Manually follows redirects hop-by-hop to capture the full redirect chain,
instead of httpx's automatic follow_redirects=True which silently resolves.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from darla.config import get_settings
from darla.utils.egress import egress_block_reason, guarded_transport
from darla.utils.http_client import _extract_filename, _random_headers

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 20

# Same-host JS targets that are client-side *fallback* handlers rather
# than real navigations.  Microsoft's authorize endpoint serves a 200
# HTML scaffold with:
#   * a real MSA handoff URL (``https://login.live.com/...``) used by JS
#   * a ``location.replace("/error.aspx?err=NNN")`` safety-net that only
#     fires if the JS handoff fails
# Our original extractor picked the error.aspx target first and followed
# it into a dead-end 404.  Any host/path pair listed here is treated as
# "don't follow in pure-HTTP mode" — the browser path will execute the
# real JS.
_DEAD_END_SAMEHOST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("login.microsoftonline.com", re.compile(r"^/error\.aspx")),
    ("login.microsoftonline.com", re.compile(r"^/nomatch")),
    ("login.live.com", re.compile(r"^/err\.srf")),
    ("login.live.com", re.compile(r"^/nomatch")),
)


def _is_dead_end_samehost(current_url: str, candidate_url: str) -> bool:
    """Return True if ``candidate_url`` is a known client-side fallback
    handler on the same host as ``current_url`` — a navigation we should
    NOT follow in pure-HTTP mode because it displaces the real flow.
    """
    try:
        cur = urlparse(current_url)
        cand = urlparse(candidate_url)
    except Exception:
        return False
    # Only applies when target is same-host (relative or explicit).
    cand_host = cand.hostname or cur.hostname
    if cand_host != cur.hostname:
        return False
    for host, path_re in _DEAD_END_SAMEHOST_PATTERNS:
        if cur.hostname == host and path_re.match(cand.path or ""):
            return True
    return False


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None = None
    server: str | None = None


@dataclass
class RedirectChain:
    hops: list[RedirectHop] = field(default_factory=list)
    final_url: str = ""
    total_redirects: int = 0

    def to_dict(self) -> dict:
        return {
            "hops": [
                {"url": h.url, "status_code": h.status_code,
                 "location": h.location, "server": h.server}
                for h in self.hops
            ],
            "final_url": self.final_url,
            "total_redirects": self.total_redirects,
        }

    @property
    def intermediate_urls(self) -> list[str]:
        """URLs from redirect hops (excluding initial and final)."""
        return [h.location for h in self.hops if h.location and h.location != self.final_url]


def _extract_js_redirect(body: str, base_url: str) -> str | None:
    """Extract a redirect URL from meta-refresh or JavaScript location patterns.

    Returns the absolute URL if a client-side redirect is found, else None.
    Only considers the first 200 KB of the body to avoid scanning huge files.

    When a page contains multiple candidate targets (common on IdP
    handoff pages like ``login.microsoftonline.com/*/oauth2/v2.0/authorize``
    which ship both a real cross-host MSA redirect and a same-host
    ``/error.aspx`` fallback), we:

      1. filter out known same-host dead-end fallback handlers
         (see ``_DEAD_END_SAMEHOST_PATTERNS``),
      2. prefer a cross-host candidate over a same-host one,
      3. fall back to the first surviving candidate in body order.

    This fixes the Azure OAuth AITM case where an attacker-registered
    MSA app would redirect the victim via ``login.live.com`` to an AITM
    proxy, but our old "first match wins" logic followed a client-side
    ``location.replace('/error.aspx?err=504')`` safety-net into a
    dead-end 404 — making live kits look dead.
    """
    body = body[:200_000]

    candidates: list[str] = []

    # 1. <meta http-equiv="refresh" content="N; url=...">
    for m in re.finditer(
        r'<meta\s[^>]*http-equiv\s*=\s*["\']?refresh["\']?\s[^>]*'
        r'content\s*=\s*["\']?\s*\d+\s*;\s*url\s*=\s*([^"\'>\s]+)',
        body, re.IGNORECASE,
    ):
        candidates.append(urljoin(base_url, m.group(1).strip()))

    # 2. window.location / location.href / location.replace / location.assign
    js_patterns = [
        # window.location.href = "..." / window.location = "..."
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        # window.location.replace("...") / window.location.assign("...")
        r'(?:window\.)?location\.(?:replace|assign)\s*\(\s*["\']([^"\']+)["\']\s*\)',
    ]
    for pattern in js_patterns:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            target = m.group(1).strip()
            # Ignore self-referencing patterns like location.href = location.href
            if "location" in target.lower():
                continue
            # Ignore javascript: URIs and anchors
            if target.startswith(("javascript:", "#")):
                continue
            candidates.append(urljoin(base_url, target))

    if not candidates:
        return None

    # De-duplicate while preserving first-seen order (body order matters
    # as a tiebreaker for same-class candidates).
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    # Drop known same-host dead-end fallback handlers.
    live = [c for c in unique if not _is_dead_end_samehost(base_url, c)]
    if not live:
        # Every candidate was a dead-end fallback (e.g. the only JS
        # target was ``/error.aspx?err=504``).  Treat the current page
        # AS the final page — don't follow into a guaranteed 404.
        return None

    # Prefer cross-host candidates over same-host ones.  Cross-host
    # navigation on an IdP page is the real handoff; same-host is
    # almost always some internal shuffle we don't need to follow.
    try:
        base_host = urlparse(base_url).hostname
    except Exception:
        base_host = None

    def _is_cross_host(u: str) -> bool:
        try:
            return urlparse(u).hostname not in (None, "", base_host)
        except Exception:
            return False

    cross_host = [c for c in live if _is_cross_host(c)]
    if cross_host:
        return cross_host[0]
    return live[0]


class RedirectTracker:
    """Download a URL while capturing the full redirect chain."""

    def download_with_redirects(
        self,
        url: str,
        dest_dir: str,
        max_size_mb: int = 50,
    ) -> tuple[Path | None, str, RedirectChain]:
        """Download a URL, capturing each redirect hop.

        Returns (filepath, reason, chain) — same interface as download_file()
        but with the redirect chain appended.
        """
        settings = get_settings()
        chain = RedirectChain()
        dest_path = Path(dest_dir)
        dest_path.mkdir(parents=True, exist_ok=True)
        max_bytes = max_size_mb * 1024 * 1024

        current_url = url
        redirect_codes = {301, 302, 303, 307, 308}

        try:
            # Use follow_redirects=False to capture each hop
            with httpx.Client(
                headers=_random_headers(),
                timeout=settings.download_timeout,
                follow_redirects=False,
                # Every hop's connection is checked (darla.utils.egress).
                transport=guarded_transport(),
            ) as client:
                # Follow redirects manually
                for _ in range(MAX_REDIRECTS):
                    response = client.get(current_url)

                    if response.status_code in redirect_codes:
                        location = response.headers.get("location", "")
                        chain.hops.append(RedirectHop(
                            url=current_url,
                            status_code=response.status_code,
                            location=location,
                            server=response.headers.get("server"),
                        ))
                        chain.total_redirects += 1

                        if not location:
                            chain.final_url = current_url
                            return None, "Redirect with no Location header", chain

                        # Handle relative redirects
                        if location.startswith("/"):
                            from urllib.parse import urlparse
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"

                        current_url = location
                        continue

                    # Non-redirect response — this is the final destination
                    chain.final_url = current_url
                    response.raise_for_status()

                    # Check for JS/meta-refresh redirects in HTML responses
                    content_type = response.headers.get("content-type", "")
                    if "html" in content_type or "text" in content_type:
                        try:
                            body_text = response.text
                        except Exception:
                            body_text = response.content.decode("utf-8", errors="ignore")
                        js_target = _extract_js_redirect(body_text, current_url)
                        if js_target and js_target != current_url:
                            chain.hops.append(RedirectHop(
                                url=current_url,
                                status_code=response.status_code,
                                location=js_target,
                                server=response.headers.get("server"),
                            ))
                            chain.total_redirects += 1
                            logger.info(
                                "JS/meta redirect detected: %s -> %s",
                                current_url, js_target,
                            )
                            current_url = js_target
                            continue

                    # Stream the final response body to disk
                    filename = _extract_filename(current_url, response)
                    filepath = dest_path / filename

                    # For non-streaming response, write directly
                    content = response.content
                    if len(content) > max_bytes:
                        return None, f"Exceeded size limit ({max_size_mb} MB)", chain

                    filepath.write_bytes(content)
                    logger.info(
                        "Downloaded %s (%d bytes, %d redirects) to %s",
                        url, len(content), chain.total_redirects, filepath,
                    )
                    return filepath, "ok", chain

                # Exceeded max redirects
                chain.final_url = current_url
                return None, f"Exceeded max redirects ({MAX_REDIRECTS})", chain

        except httpx.HTTPStatusError as e:
            chain.final_url = current_url
            return None, f"HTTP {e.response.status_code}", chain
        except httpx.TimeoutException:
            chain.final_url = current_url
            return None, "Connection timed out", chain
        except httpx.RequestError as e:
            # A blocked hop keeps final_url = the internal target the lure
            # tried to reach — recorded in the redirect chain as evidence.
            chain.final_url = current_url
            if blocked := egress_block_reason(e):
                logger.warning("Blocked redirect hop %s: %s", current_url, blocked)
                return None, blocked, chain
            return None, f"Request error: {type(e).__name__}", chain
        except Exception as e:
            chain.final_url = current_url
            return None, f"Unexpected error: {type(e).__name__}", chain
