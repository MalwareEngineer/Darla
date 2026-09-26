"""External JS fetcher — follow <script src="..."> in rendered phishing pages.

Parses HTML files for external script references, filters out benign CDNs,
fetches suspicious JS files, and saves them into the kit's extract directory
so the IOC extractor and YARA scanner can analyze them.

Also probes discovered PHP endpoints — misconfigured phishing servers often
serve raw PHP source when accessed directly.
"""

import hashlib
import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

from darla.analysis.patterns import (
    extract_root_domain,
    is_benign_url,
)
from darla.utils.http_client import get_sync_client

logger = logging.getLogger(__name__)

# Match <script src="..."> in HTML, and <script href|xlink:href="..."> in SVG.
# Accepts optional namespace prefix on <script> (e.g. <svg:script>).
SCRIPT_SRC_RE = re.compile(
    r"""<\s*(?:[a-zA-Z][\w-]*:)?script\b[^>]*?
        (?:src|xlink:href|href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE | re.VERBOSE,
)

# Match URLs in JS content (for recursive following and PHP probing)
JS_URL_RE = re.compile(
    r"""(?:['"`])(\s*https?://[^\s'"<>`\]\\]{10,})""",
    re.IGNORECASE,
)

# Match document.createElement("script").src = "..." pattern
JS_SCRIPT_CREATE_RE = re.compile(
    r"""\.src\s*=\s*['"](\s*https?://[^\s'"<>`\]\\]+\.js[^'"]*)['"]""",
    re.IGNORECASE,
)

# Match fetch("https://..."), XMLHttpRequest.open("GET", "https://..."),
# and new URL("https://...") — the dynamic loaders inline SVG scripts
# and obfuscated JS actually use.
JS_DYNAMIC_URL_RE = re.compile(
    r"""(?:
        \bfetch\s*\(\s*['"`](https?://[^'"`\s]+)['"`]
      | \.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"`](https?://[^'"`\s]+)['"`]
      | \bimportScripts\s*\(\s*['"`](https?://[^'"`\s]+)['"`]
      | \bnew\s+Worker\s*\(\s*['"`](https?://[^'"`\s]+)['"`]
      | \bnew\s+URL\s*\(\s*['"`](https?://[^'"`\s]+)['"`]
      | (?:window\.)?location(?:\.href)?\s*=\s*['"`](https?://[^'"`\s]+)['"`]
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# File extensions that indicate an HTML landing page (terminal node) rather than
# a JS/script resource (intermediate node).
_HTML_EXTENSIONS = frozenset({
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".cfm",
})
_JS_EXTENSIONS = frozenset({
    ".js", ".mjs", ".cjs", ".json", ".txt",
})

# Content types we accept for JS files
ACCEPTABLE_JS_CONTENT_TYPES = frozenset({
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/plain",
    "text/html",  # Some servers serve JS/PHP with wrong content-type
    "application/json",
})

# Files we scan for script src references
SCANNABLE_EXTENSIONS = frozenset({".html", ".htm", ".js", ".deob.js", ".svg"})


@dataclass
class JSFetchResult:
    """Results from external JS fetching."""

    files_fetched: int = 0
    files_skipped_benign: int = 0
    files_skipped_error: int = 0
    urls_discovered: list[str] = field(default_factory=list)
    urls_fetched: list[str] = field(default_factory=list)
    urls_skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    php_sources_found: int = 0
    saved_files: list[str] = field(default_factory=list)
    # URLs that look like HTML landing pages rather than JS resources.
    # These are hand-offs for the chain crawler to spawn child kits from.
    terminal_urls: list[str] = field(default_factory=list)


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a private/loopback IP (SSRF guard)."""
    try:
        for _family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if ip.startswith(("10.", "192.168.", "127.", "0.",
                              "172.16.", "172.17.", "172.18.", "172.19.",
                              "172.20.", "172.21.", "172.22.", "172.23.",
                              "172.24.", "172.25.", "172.26.", "172.27.",
                              "172.28.", "172.29.", "172.30.", "172.31.",
                              "169.254.")):
                return True
            if ip == "::1" or ip.startswith("fe80:") or ip.startswith("fc") or ip.startswith("fd"):
                return True
    except (socket.gaierror, OSError):
        return False  # DNS failure — not private, but fetch will fail anyway
    return False


def _sanitize_filename(url: str) -> str:
    """Create a safe filename from a URL path."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    name = path.split("/")[-1] if path else "index.js"
    # Strip non-alphanumeric chars except dots, hyphens, underscores
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    if not name or name.startswith("."):
        name = "fetched.js"
    # Ensure .js extension for JS files
    if not any(name.endswith(ext) for ext in (".js", ".php", ".json", ".txt")):
        name += ".js"
    # Cap length
    if len(name) > 80:
        name = name[:60] + "_" + hashlib.md5(url.encode()).hexdigest()[:8] + name[name.rfind("."):]
    return name


class ExternalJSFetcher:
    """Fetch external JS sources referenced in phishing kit HTML files."""

    def __init__(
        self,
        source_url: str | None = None,
        max_depth: int = 2,
        max_files: int = 10,
        max_size_kb: int = 512,
        timeout: int = 15,
    ):
        self._source_url = source_url
        self._source_root = None
        if source_url:
            try:
                host = urlparse(source_url).hostname
                if host:
                    self._source_root = extract_root_domain(host.lower())
            except Exception:
                pass

        self._max_depth = max_depth
        self._max_files = max_files
        self._max_size_bytes = max_size_kb * 1024
        self._timeout = timeout
        self._fetched_urls: set[str] = set()
        self._total_fetched = 0

    def fetch_from_directory(self, extract_dir: str) -> JSFetchResult:
        """Scan all HTML/JS files in a directory and fetch external JS."""
        result = JSFetchResult()
        base = Path(extract_dir)
        if not base.is_dir():
            return result

        # Create output directory for fetched JS
        js_dir = base / "_external_js"

        # Load existing manifest (dedup on retry)
        manifest_path = js_dir / "_manifest.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
                self._fetched_urls = set(manifest.get("fetched_urls", []))
            except Exception:
                pass

        # Collect all scannable files
        for fpath in sorted(base.rglob("*")):
            if not fpath.is_file():
                continue
            # Skip our own output directory
            if "_external_js" in fpath.parts:
                continue
            # Strip attacker-appended trailing dots/spaces from the filename
            # before reading the suffix — phishing samples use names like
            # "ATT021.svg.." so the naive Path.suffix returns "." and misses.
            _norm_name = fpath.name.rstrip(". ")
            _norm_suffix = Path(_norm_name).suffix.lower()
            # Also accept extensionless files that look like HTML
            if _norm_suffix not in SCANNABLE_EXTENSIONS and _norm_suffix:
                continue
            self._process_file(fpath, js_dir, result, depth=0)

        # Save manifest
        if result.files_fetched > 0:
            js_dir.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps({
                "fetched_urls": list(self._fetched_urls),
                "files_fetched": result.files_fetched,
            }, indent=2))

        return result

    def fetch_from_file(self, filepath: str) -> JSFetchResult:
        """Scan a single file for external JS references."""
        result = JSFetchResult()
        fpath = Path(filepath)
        if not fpath.is_file():
            return result

        js_dir = fpath.parent / "_external_js"
        self._process_file(fpath, js_dir, result, depth=0)

        if result.files_fetched > 0:
            js_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = js_dir / "_manifest.json"
            manifest_path.write_text(json.dumps({
                "fetched_urls": list(self._fetched_urls),
                "files_fetched": result.files_fetched,
            }, indent=2))

        return result

    def _process_file(
        self, fpath: Path, js_dir: Path, result: JSFetchResult, depth: int,
    ) -> None:
        """Extract script URLs from a file and fetch them."""
        if depth > self._max_depth:
            return
        if self._total_fetched >= self._max_files:
            return

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        # Determine base URL for resolving relative script src paths
        base_url = self._source_url

        # Extract script src URLs from HTML
        urls = self._extract_script_urls(content, base_url)

        # Also check JS content for dynamically created script tags
        urls.extend(self._extract_js_script_urls(content))

        for url in urls:
            result.urls_discovered.append(url)

            # Landing-page URLs hand off to the chain crawler for
            # browser-render child kits, not the JS fetcher.
            if self._classify_url(url) == "terminal":
                if url not in result.terminal_urls and not is_benign_url(url):
                    result.terminal_urls.append(url)
                continue

            if not self._should_fetch(url):
                result.files_skipped_benign += 1
                result.urls_skipped.append(url)
                continue

            saved_path = self._fetch_and_save(url, js_dir, result)
            if saved_path:
                # Recursively scan the fetched JS for more URLs
                self._process_file(saved_path, js_dir, result, depth=depth + 1)

                # Probe for PHP endpoints found in the fetched JS
                self._probe_php_from_content(saved_path, js_dir, result)

    def _extract_script_urls(
        self, content: str, base_url: str | None,
    ) -> list[str]:
        """Extract and resolve <script src|href|xlink:href="..."> URLs.

        Covers HTML <script src=>, SVG 1.1 <script xlink:href=>, and
        SVG 2 <script href=>.
        """
        # file:// base URLs can't meaningfully resolve relative refs and
        # attempting it risks local file disclosure on misconfigured hosts.
        base_is_file = bool(base_url and base_url.startswith("file://"))

        urls: list[str] = []
        for match in SCRIPT_SRC_RE.finditer(content):
            src = match.group(1).strip()
            if not src or src.startswith(("data:", "javascript:", "blob:")):
                continue
            if not src.startswith(("http://", "https://")):
                if base_is_file or not base_url:
                    continue  # Skip relative refs without a usable base
                src = urljoin(base_url, src)
            urls.append(src)
        return urls

    def _extract_js_script_urls(self, content: str) -> list[str]:
        """Extract URLs that JS loads dynamically.

        Catches the full family of inline-script loader patterns:
        - ``elem.src = "https://..."`` (existing)
        - ``fetch("https://...")``
        - ``xhr.open("GET", "https://...")``
        - ``importScripts("https://...")``
        - ``new Worker("https://...")``
        - ``new URL("https://...")``
        - ``location(.href) = "https://..."``
        """
        urls: list[str] = []
        for match in JS_SCRIPT_CREATE_RE.finditer(content):
            url = match.group(1).strip()
            if url.startswith(("http://", "https://")):
                urls.append(url)
        for match in JS_DYNAMIC_URL_RE.finditer(content):
            # Multiple alternation groups — pick the one that matched.
            for group in match.groups():
                if group and group.startswith(("http://", "https://")):
                    urls.append(group.strip())
                    break
        return urls

    def _classify_url(self, url: str) -> str:
        """Return ``"js"`` or ``"terminal"`` based on URL shape.

        Terminal URLs look like HTML landing pages — navigation targets,
        not script resources. These get handed off to the chain crawler.
        """
        try:
            path = urlparse(url).path.lower()
        except Exception:
            return "js"

        # Trailing slash or empty path → likely a landing page
        if not path or path.endswith("/"):
            return "terminal"

        # Explicit extension tells us directly
        last_dot = path.rfind(".")
        if last_dot > path.rfind("/"):
            ext = path[last_dot:]
            if ext in _JS_EXTENSIONS:
                return "js"
            if ext in _HTML_EXTENSIONS:
                return "terminal"

        # Paths with no extension in their final segment lean terminal
        # (e.g. /login, /signin, /o/oauth2/deviceauth).
        return "terminal"

    def _should_fetch(self, url: str) -> bool:
        """Determine if a URL should be fetched (not benign, not already done)."""
        if url in self._fetched_urls:
            return False
        if self._total_fetched >= self._max_files:
            return False

        # Only fetch http/https
        if not url.startswith(("http://", "https://")):
            return False

        # Skip benign CDN URLs (jQuery, Google Hosted, etc.)
        if is_benign_url(url):
            return False

        # Skip URLs on the same root domain as the kit source
        # (the rendered page itself is already analyzed)
        try:
            hostname = urlparse(url).hostname
            if hostname:
                root = extract_root_domain(hostname.lower())
                if root == self._source_root:
                    return False
        except Exception:
            pass

        return True

    def _fetch_and_save(
        self, url: str, js_dir: Path, result: JSFetchResult,
    ) -> Path | None:
        """Fetch a URL and save it to the JS output directory."""
        self._fetched_urls.add(url)

        # SSRF guard: check for private IPs
        try:
            hostname = urlparse(url).hostname
            if hostname and _is_private_ip(hostname):
                logger.debug("Skipping private IP for %s", url)
                result.errors.append(f"private_ip:{url}")
                result.files_skipped_error += 1
                return None
        except Exception:
            pass

        try:
            with get_sync_client(timeout=self._timeout) as client:
                response = client.get(url)

            if response.status_code != 200:
                logger.debug(
                    "External JS fetch %s returned %d",
                    url, response.status_code,
                )
                result.errors.append(f"http_{response.status_code}:{url}")
                result.files_skipped_error += 1
                return None

            # Validate content-type
            content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type and content_type not in ACCEPTABLE_JS_CONTENT_TYPES:
                logger.debug(
                    "External JS fetch %s has unexpected content-type: %s",
                    url, content_type,
                )
                result.errors.append(f"bad_content_type:{content_type}:{url}")
                result.files_skipped_error += 1
                return None

            # Size guard
            content = response.content
            if len(content) > self._max_size_bytes:
                logger.debug(
                    "External JS fetch %s too large: %d bytes",
                    url, len(content),
                )
                result.errors.append(f"too_large:{len(content)}:{url}")
                result.files_skipped_error += 1
                return None

            # Save to disk
            js_dir.mkdir(parents=True, exist_ok=True)
            filename = _sanitize_filename(url)
            dest = js_dir / filename

            # Handle filename collisions
            if dest.exists():
                stem = dest.stem
                short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
                dest = js_dir / f"{stem}_{short_hash}{dest.suffix}"

            dest.write_bytes(content)
            self._total_fetched += 1

            result.files_fetched += 1
            result.urls_fetched.append(url)
            result.saved_files.append(str(dest))

            logger.info(
                "Fetched external JS: %s → %s (%d bytes)",
                url, dest.name, len(content),
            )

            # Rate limiting between fetches
            time.sleep(0.5)

            return dest

        except Exception as e:
            logger.debug("Failed to fetch external JS %s: %s", url, e)
            result.errors.append(f"fetch_error:{url}:{e}")
            result.files_skipped_error += 1
            return None

    def _probe_php_from_content(
        self, js_path: Path, js_dir: Path, result: JSFetchResult,
    ) -> None:
        """Scan fetched JS for PHP endpoint URLs and try to fetch source."""
        if self._total_fetched >= self._max_files:
            return

        try:
            content = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        for match in JS_URL_RE.finditer(content):
            url = match.group(1).strip()
            if not url.endswith(".php"):
                continue
            if url in self._fetched_urls:
                continue
            if is_benign_url(url):
                continue
            if self._total_fetched >= self._max_files:
                break

            # Try to fetch the PHP endpoint
            self._fetched_urls.add(url)
            try:
                with get_sync_client(timeout=self._timeout) as client:
                    response = client.get(url)

                if response.status_code != 200:
                    continue

                text = response.text
                # Check if server returned raw PHP source
                if "<?php" in text or "<?=" in text:
                    js_dir.mkdir(parents=True, exist_ok=True)
                    filename = _sanitize_filename(url)
                    dest = js_dir / filename
                    if dest.exists():
                        short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
                        dest = js_dir / f"{dest.stem}_{short_hash}{dest.suffix}"
                    dest.write_text(text, encoding="utf-8")
                    self._total_fetched += 1
                    result.files_fetched += 1
                    result.urls_fetched.append(url)
                    result.saved_files.append(str(dest))
                    result.php_sources_found += 1
                    logger.info(
                        "Fetched PHP source: %s → %s (%d bytes)",
                        url, dest.name, len(text),
                    )
                    time.sleep(0.5)

            except Exception as e:
                logger.debug("Failed to probe PHP %s: %s", url, e)
