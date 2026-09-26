"""IOC extraction engine for phishing kit source files."""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from darla.analysis.patterns import (
    _JS_OBJECT_PREFIXES,
    _JS_PRONE_TLDS,
    AITM_AUTH_ENDPOINTS,
    BENIGN_DOMAINS,
    BENIGN_URL_EXTENSIONS,
    BENIGN_URL_ROOT_DOMAINS,
    BITCOIN_PATTERN,
    C2_KEYWORDS,
    C2_URL_PATTERN,
    CLOUDFLARE_CHALLENGE_FILENAME_RE,
    CSS_JUNK_IN_URL,
    DOMAIN_PATTERN,
    EMAIL_EXCLUSIONS,
    EMAIL_PATTERN,
    EMAIL_PLACEHOLDER_LOCALS,
    ETHEREUM_PATTERN,
    FALSE_DOMAIN_EXTENSIONS,
    IP_ECHO_FILENAME_FRAGMENTS,
    IPV4_PATTERN,
    JS_CONCAT_BOUNDARY,
    JS_FALSE_DOMAINS,
    ORIGIN_BENIGN,
    PHONE_PATTERN,
    PHP_MAIL_PATTERN,
    PHP_MAIL_TO_PATTERN,
    PRIVATE_IP_PREFIXES,
    SMTP_HOST_EXCLUSIONS,
    SMTP_HOST_PATTERN,
    SMTP_PASS_PATTERN,
    SMTP_USER_PATTERN,
    TELEGRAM_API_PATTERN,
    TELEGRAM_BOT_TOKEN_PATTERN,
    TELEGRAM_CHAT_ID_PATTERN,
    TELEGRAM_CONTEXT_MARKERS,
    TELEGRAM_HANDLE_EXCLUSIONS,
    TELEGRAM_HANDLE_PATTERN,
    TELEGRAM_URL_HANDLE_PATTERN,
    URL_TRAILING_JUNK,
    VALID_TLDS,
    WEBSOCKET_URL_PATTERN,
    classify_origin,
    extract_root_domain,
    is_benign_url,
)
from darla.models.indicator import IndicatorType

logger = logging.getLogger(__name__)

# Guard rails for pathological files (the P99 file is ~50 KB; the outlier
# that took 7,794 seconds was a multi-MB minified HTML blob).
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB — skip files larger than this
MAX_SCAN_SECONDS = 120  # 2 minutes per file — abort and return partial IOCs
MAX_LINE_LENGTH = 100_000  # 100 KB — truncate longer lines before regex (minified JS/HTML)

PROCESSABLE_EXTENSIONS = {
    ".php", ".js", ".html", ".htm", ".txt", ".json",
    ".conf", ".ini", ".xml", ".inc",
}


@dataclass
class ExtractedIOC:
    type: IndicatorType
    value: str
    source_file: str
    line_number: int
    context: str
    confidence: int


@dataclass
class ExtractionResult:
    iocs: list[ExtractedIOC] = field(default_factory=list)
    files_processed: int = 0
    errors: list[str] = field(default_factory=list)


class ResourceManifest:
    """Maps on-disk browser-captured file paths back to their origin URLs.

    Written by browser_downloader._on_response into
    ``_browser_resources/_manifest.json``.  The IOC scanner consults it to
    decide whether a captured resource came from attacker-controlled
    infrastructure (scan) or a benign third-party CDN (skip).
    """

    def __init__(self, by_relative_path: dict[str, dict]):
        self._entries = by_relative_path

    @classmethod
    def load(cls, base_dir: str) -> "ResourceManifest":
        manifest_path = Path(base_dir) / "_browser_resources" / "_manifest.json"
        if not manifest_path.exists():
            return cls({})
        try:
            entries = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug("Failed to read manifest at %s: %s", manifest_path, e)
            return cls({})
        # Normalize keys to forward-slash relative paths for cross-platform
        # comparison against os.path.relpath() output.
        by_path: dict[str, dict] = {}
        for entry in entries if isinstance(entries, list) else []:
            fname = entry.get("filename")
            if isinstance(fname, str):
                by_path[fname.replace("\\", "/")] = entry
        return cls(by_path)

    def lookup(self, relative_path: str) -> dict | None:
        return self._entries.get(relative_path.replace("\\", "/"))


class IOCExtractor:
    """Scans phishing kit files for indicators of compromise."""

    def __init__(self, source_url: str | None = None):
        """Initialize with optional source URL for same-domain filtering.

        URLs on the same root domain as source_url are skipped — they're
        internal kit links (cloned page paths), not separate C2 infrastructure.
        """
        self._source_root_domain: str | None = None
        if source_url:
            try:
                host = urlparse(source_url).hostname
                if host:
                    self._source_root_domain = extract_root_domain(host)
            except Exception:
                pass

    def scan_directory(self, directory: str) -> ExtractionResult:
        result = ExtractionResult()
        manifest = ResourceManifest.load(directory)
        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                relative = os.path.relpath(filepath, directory).replace("\\", "/")
                # requests.json is extracted via the structured network-IOC
                # path (extract_network_iocs_from_requests_json), not via
                # regex scanning as if it were kit source.
                if relative == "requests.json":
                    continue
                # The manifest itself isn't content to scan.
                if relative.endswith("_browser_resources/_manifest.json"):
                    continue
                ext = Path(filepath).suffix.lower()
                if ext in PROCESSABLE_EXTENSIONS:
                    try:
                        file_iocs = self._scan_file(
                            filepath, directory, manifest=manifest,
                        )
                        result.iocs.extend(file_iocs)
                        result.files_processed += 1
                    except Exception as e:
                        result.errors.append(f"{filepath}: {e}")
        result.iocs = self._deduplicate(result.iocs)
        return result

    def scan_content(
        self,
        content: str,
        source_file: str = "<string>",
        *,
        skip_crypto_and_ip: bool = False,
        skip_ip_only: bool = False,
    ) -> list[ExtractedIOC]:
        """Scan a string for IOCs (useful for testing or one-off analysis).

        ``skip_crypto_and_ip`` suppresses crypto-wallet and IP extractors for
        files that are known to produce false positives of both types
        (e.g. Cloudflare challenge pages).  ``skip_ip_only`` suppresses just
        IP extraction — used for IP-echo-service response bodies whose
        "IP" is the visitor's own public address.
        """
        iocs: list[ExtractedIOC] = []
        lines = content.split("\n")
        deadline = time.monotonic() + MAX_SCAN_SECONDS

        for line_num, line in enumerate(lines, start=1):
            # Check timeout every 500 lines
            if line_num % 500 == 0 and time.monotonic() > deadline:
                logger.warning(
                    "IOC extraction timed out after %ds on %s at line %d/%d, "
                    "returning %d partial IOCs",
                    MAX_SCAN_SECONDS, source_file, line_num, len(lines), len(iocs),
                )
                break

            # Truncate mega-lines (minified JS/HTML) to prevent catastrophic
            # regex backtracking on a single line that never hits the timeout
            if len(line) > MAX_LINE_LENGTH:
                logger.debug(
                    "Truncating %d-char line at %s:%d to %d chars",
                    len(line), source_file, line_num, MAX_LINE_LENGTH,
                )
                line = line[:MAX_LINE_LENGTH]

            iocs.extend(self._extract_emails(line, source_file, line_num))
            iocs.extend(self._extract_telegram_tokens(line, source_file, line_num))
            iocs.extend(self._extract_telegram_chat_ids(line, source_file, line_num))
            iocs.extend(self._extract_telegram_handles(line, source_file, line_num))

            # Extract URLs first, then pass their hostnames to domain extraction
            # so we don't double-count domains already captured in URLs
            url_iocs = self._extract_urls(line, source_file, line_num)
            iocs.extend(url_iocs)
            url_hostnames = set()
            for ioc in url_iocs:
                try:
                    hostname = urlparse(ioc.value).hostname
                    if hostname:
                        url_hostnames.add(hostname.lower())
                except Exception:
                    pass

            iocs.extend(self._extract_domains(
                line, source_file, line_num, skip_domains=url_hostnames,
            ))
            if not (skip_crypto_and_ip or skip_ip_only):
                iocs.extend(self._extract_ips(line, source_file, line_num))
            iocs.extend(self._extract_smtp_creds(line, source_file, line_num))
            if not skip_crypto_and_ip:
                iocs.extend(
                    self._extract_crypto_wallets(line, source_file, line_num)
                )
            iocs.extend(self._extract_phone_numbers(line, source_file, line_num))
            iocs.extend(self._extract_aitm_indicators(line, source_file, line_num))

        return self._deduplicate(iocs)

    def scan_file(self, filepath: str) -> ExtractionResult:
        """Scan a single file for IOCs. Returns an ExtractionResult."""
        result = ExtractionResult()
        try:
            file_iocs = self._scan_file(filepath, str(Path(filepath).parent))
            result.iocs.extend(file_iocs)
            result.files_processed = 1
        except Exception as e:
            result.errors.append(f"{filepath}: {e}")
        result.iocs = self._deduplicate(result.iocs)
        return result

    def _scan_file(
        self,
        filepath: str,
        base_dir: str,
        *,
        manifest: "ResourceManifest | None" = None,
    ) -> list[ExtractedIOC]:
        relative_path = os.path.relpath(filepath, base_dir)
        relative_posix = relative_path.replace("\\", "/")

        # Skip oversized files — they cause multi-hour regex stalls
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            return []
        if file_size > MAX_FILE_SIZE_BYTES:
            logger.warning(
                "Skipping IOC extraction for %s (%d bytes > %d byte limit)",
                relative_path, file_size, MAX_FILE_SIZE_BYTES,
            )
            return []

        # Extensionless files (e.g. "authorize") are common in phishing kits.
        # Sniff the first bytes — if it looks like text/HTML, process it.
        ext = Path(filepath).suffix.lower()
        if ext and ext not in PROCESSABLE_EXTENSIONS:
            return []
        if not ext:
            try:
                with open(filepath, "rb") as f:
                    head = f.read(512)
                if not head or not self._looks_like_text(head):
                    return []
            except Exception:
                return []

        # Origin-aware gating for browser-captured resources.  Files served
        # by known-benign CDNs are skipped entirely — jQuery, Angular,
        # crypto-js, Popper, Qualified's widget, Microsoft auth CDNs, etc.
        # all live here and produce only false positives.  Attacker-hosted
        # JS (unclassified origin) still goes through the full extractor.
        origin_url: str | None = None
        if manifest is not None:
            entry = manifest.lookup(relative_posix)
            if entry:
                origin_url = entry.get("url")
                origin_class = classify_origin(
                    origin_url, self._source_root_domain,
                )
                if origin_class == ORIGIN_BENIGN:
                    logger.debug(
                        "Skipping IOC scan of %s (benign origin %s)",
                        relative_posix, origin_url,
                    )
                    return []

        # Cloudflare challenge pages: Base58-ish ray tokens trip the
        # crypto-wallet regex, and the "-1.2.1.1-" version fragment trips
        # IPv4.  Skip both extractors on those specific files regardless
        # of origin classification.
        filename_only = os.path.basename(relative_posix)
        skip_crypto_and_ip = bool(
            CLOUDFLARE_CHALLENGE_FILENAME_RE.search(filename_only)
        )

        # IP-echo service response bodies (api.ipify.org.json and friends)
        # contain the visitor's own public IP, not attacker infrastructure.
        skip_ip_only = any(
            frag in relative_posix for frag in IP_ECHO_FILENAME_FRAGMENTS
        )

        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        return self.scan_content(
            content,
            relative_path,
            skip_crypto_and_ip=skip_crypto_and_ip,
            skip_ip_only=skip_ip_only,
        )

    @staticmethod
    def _looks_like_text(head: bytes) -> bool:
        """Sniff first bytes to decide if an extensionless file is text."""
        # Check for HTML/XML markers
        head_lower = head.lower()
        if any(marker in head_lower for marker in (
            b"<!doctype", b"<html", b"<script", b"<?php", b"<?xml",
        )):
            return True
        # Check if mostly printable ASCII / UTF-8
        try:
            text = head.decode("utf-8", errors="strict")
            printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
            return printable / len(text) > 0.85
        except (UnicodeDecodeError, ZeroDivisionError):
            return False

    def _extract_emails(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []

        # High-confidence: PHP mail() targets
        for pattern in (PHP_MAIL_PATTERN, PHP_MAIL_TO_PATTERN):
            for match in pattern.finditer(line):
                email = match.group(1)
                domain = email.split("@")[1].lower()
                root = extract_root_domain(domain)
                if domain not in EMAIL_EXCLUSIONS and root not in BENIGN_DOMAINS:
                    results.append(ExtractedIOC(
                        type=IndicatorType.EMAIL,
                        value=email,
                        source_file=source_file,
                        line_number=line_num,
                        context=line[:200],
                        confidence=90,
                    ))

        # Standard email extraction
        for match in EMAIL_PATTERN.finditer(line):
            email = match.group(0)
            # Skip retina image references (logo@2x.png, icon@3x.jpg)
            if "@" in email:
                after_at = email.split("@", 1)[1]
                if after_at and after_at[0].isdigit():
                    continue
            local_part = email.split("@")[0].lower()
            domain = email.split("@")[1].lower()
            if domain in EMAIL_EXCLUSIONS:
                continue
            # Skip placeholder emails (your@, user@, test@, etc.)
            if local_part in EMAIL_PLACEHOLDER_LOCALS:
                continue
            # Also check root domain (catches uuid@o293668.ingest.sentry.io etc.)
            root = extract_root_domain(domain)
            if root in BENIGN_DOMAINS:
                continue
            # Skip if already captured by mail() patterns
            if any(ioc.value == email for ioc in results):
                continue
            confidence = 70
            if any(
                kw in line.lower()
                for kw in ("send", "mail(", "smtp", "result", "$to")
            ):
                confidence = 85
            results.append(ExtractedIOC(
                type=IndicatorType.EMAIL,
                value=email,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=confidence,
            ))
        return results

    def _extract_telegram_tokens(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in TELEGRAM_BOT_TOKEN_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.TELEGRAM_BOT_TOKEN,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=95,
            ))
        return results

    def _extract_telegram_chat_ids(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in TELEGRAM_CHAT_ID_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.TELEGRAM_CHAT_ID,
                value=match.group(1),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=85,
            ))
        return results

    def _extract_urls(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []

        # Telegram API URLs (high confidence — definite exfil)
        telegram_urls = set()
        for match in TELEGRAM_API_PATTERN.finditer(line):
            url = URL_TRAILING_JUNK.sub("", match.group(0))
            telegram_urls.add(url)
            results.append(ExtractedIOC(
                type=IndicatorType.C2_URL,
                value=url,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=95,
            ))

        # WebSocket URLs — always C2 infrastructure in phishing kits.
        # AiTM kits use wss:// for real-time credential relay.
        websocket_hosts: set[str] = set()
        for match in WEBSOCKET_URL_PATTERN.finditer(line):
            url = URL_TRAILING_JUNK.sub("", match.group(0))
            js_break = JS_CONCAT_BOUNDARY.search(url)
            if js_break:
                url = url[:js_break.start()]
            try:
                _ws_host = urlparse(url).hostname
                if not _ws_host or "." not in _ws_host:
                    continue
                _ws_host_lower = _ws_host.lower()
                if _ws_host_lower in ("localhost", "127.0.0.1"):
                    continue
                if is_benign_url(url.replace("wss://", "https://").replace("ws://", "http://")):
                    continue
                if (
                    self._source_root_domain
                    and extract_root_domain(_ws_host_lower) == self._source_root_domain
                ):
                    continue
            except Exception:
                continue
            websocket_hosts.add(_ws_host.lower())
            results.append(ExtractedIOC(
                type=IndicatorType.C2_URL,
                value=url,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=90,
            ))

        # General URL extraction — only classify as C2_URL if there are
        # strong exfiltration signals. Skip URLs that are just cloned page
        # content (Microsoft login paths, CDN assets, etc.)
        for match in C2_URL_PATTERN.finditer(line):
            url = match.group(0)

            # Strip trailing syntax junk (quotes, semicolons, commas, etc.)
            url = URL_TRAILING_JUNK.sub("", url)

            # Truncate at JS string concatenation boundaries
            js_break = JS_CONCAT_BOUNDARY.search(url)
            if js_break:
                url = url[:js_break.start()]
                try:
                    _trunc_host = urlparse(url).hostname
                    if not _trunc_host or "." not in _trunc_host or len(url) < 12:
                        continue
                except Exception:
                    continue

            url_lower = url.lower()

            # Skip if already captured as Telegram API URL
            if url in telegram_urls:
                continue
            if "api.telegram.org" in url_lower:
                continue

            # Skip URLs with CSS selector fragments
            if CSS_JUNK_IN_URL.search(url):
                continue

            # Skip benign domains using root-domain matching
            if is_benign_url(url):
                continue

            # Skip localhost and non-domain hostnames
            try:
                _host = urlparse(url).hostname
                if _host:
                    _host_lower = _host.lower()
                    if _host_lower in ("localhost", "127.0.0.1"):
                        continue
                    if "." not in _host_lower or _host_lower.endswith(
                        (".transaction", ".internal", ".local", ".invalid", ".test")
                    ):
                        continue
            except Exception:
                pass

            # Skip javascript: pseudo-protocol
            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.hostname.lower() == "javascript":
                    continue
                url_path = parsed.path.lower()
            except Exception:
                url_path = url_lower

            # Skip URLs with base64 blobs as hostname
            if "==" in url_lower or "==" in (parsed.hostname or ""):
                continue

            is_static_asset = any(
                url_path.endswith(ext) for ext in BENIGN_URL_EXTENSIONS
            )

            # Skip URLs on the same root domain as the kit's source URL.
            # These are internal kit links (cloned login page paths, OAuth
            # endpoints, etc.) — not separate C2 infrastructure. The source
            # URL already captures the phishing domain.
            if self._source_root_domain:
                url_root = extract_root_domain(parsed.hostname or "")
                if url_root == self._source_root_domain:
                    continue

            # Extract URLs with strong C2/exfil signals as C2_URL
            # (but not static assets like .js/.css).
            url_lower = url.lower()
            line_lower = line.lower()
            has_c2_signal = any(
                kw in url_lower or kw in line_lower for kw in C2_KEYWORDS
            )

            if has_c2_signal and not is_static_asset:
                results.append(ExtractedIOC(
                    type=IndicatorType.C2_URL,
                    value=url,
                    source_file=source_file,
                    line_number=line_num,
                    context=line[:200],
                    confidence=85,
                ))
            else:
                # No C2 signal or static asset — still capture the domain
                # so phishing infrastructure isn't silently dropped.
                _domain = (parsed.hostname or "").lower()
                if _domain and "." in _domain:
                    results.append(ExtractedIOC(
                        type=IndicatorType.DOMAIN,
                        value=_domain,
                        source_file=source_file,
                        line_number=line_num,
                        context=line[:200],
                        confidence=50,
                    ))
        return results

    def _extract_ips(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in IPV4_PATTERN.finditer(line):
            ip = match.group(0)
            if any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
                continue
            parts = ip.split(".")
            # Skip 172.16-31.x.x (private)
            if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                continue
            # Skip network/CIDR addresses (x.x.0.0 or x.0.0.0) — not host IPs
            if parts[3] == "0" and parts[2] == "0":
                continue
            # Reject version-string-shaped matches like "1.2.1.1", "1.3.1.1",
            # "3.5.5.3" — every octet under 10 is almost always a library
            # or Cloudflare challenge version, not a real host.
            try:
                if all(int(p) < 10 for p in parts):
                    continue
            except ValueError:
                continue
            results.append(ExtractedIOC(
                type=IndicatorType.IP_ADDRESS,
                value=ip,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=60,
            ))
        return results

    def _extract_smtp_creds(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for pattern, label in [
            (SMTP_HOST_PATTERN, "host"),
            (SMTP_USER_PATTERN, "user"),
            (SMTP_PASS_PATTERN, "pass"),
        ]:
            for match in pattern.finditer(line):
                # Each pattern has two alternations capturing in group(1) or group(2)
                value = match.group(1) or match.group(2)
                if not value:
                    continue
                # Skip known SaaS/JS false positive hosts
                if label == "host" and value.lower() in SMTP_HOST_EXCLUSIONS:
                    continue
                results.append(ExtractedIOC(
                    type=IndicatorType.SMTP_CREDENTIAL,
                    value=f"smtp_{label}={value}",
                    source_file=source_file,
                    line_number=line_num,
                    context=line[:200],
                    confidence=85,
                ))
        return results

    @staticmethod
    def _is_hex_hash(value: str) -> bool:
        """Check if a value is a hex hash (MD5/SHA) misidentified as a wallet."""
        # MD5 hashes are 32 lowercase hex chars; real Bitcoin uses Base58Check
        # (mixed case, no 0/O/I/l). All-lowercase-hex = almost certainly a hash.
        return len(value) == 32 and all(c in "0123456789abcdef" for c in value)

    @staticmethod
    def _is_url_fragment(match, line: str) -> bool:
        """Check if a regex match sits inside a URL/query-string context.

        False-positive wallets often appear in URL-encoded params, base64
        state tokens, or OAuth query strings.  We look at characters
        immediately before/after the match for URL-encoding signals.
        """
        start, end = match.start(), match.end()
        # Characters before/after the match (grab a small window)
        before = line[max(0, start - 6):start]
        after = line[end:end + 6]
        url_signals = ("%2f", "%2F", "%3a", "%3A", "%3d", "%3D",
                       "%26", "%3f", "%3F", "=", "&", "scope=",
                       "state=", "nonce=", "redirect_uri=", "client_id=")
        combined = before + after
        return any(sig in combined for sig in url_signals)

    def _extract_crypto_wallets(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in BITCOIN_PATTERN.finditer(line):
            wallet = match.group(0)
            if self._is_hex_hash(wallet):
                continue
            # Skip matches embedded in URL query strings / base64 state tokens
            if self._is_url_fragment(match, line):
                continue
            results.append(ExtractedIOC(
                type=IndicatorType.CRYPTOCURRENCY_WALLET,
                value=wallet,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=70,
            ))
        for match in ETHEREUM_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.CRYPTOCURRENCY_WALLET,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=70,
            ))
        return results

    def _extract_domains(
        self, line: str, source_file: str, line_num: int,
        skip_domains: set[str] | None = None,
    ) -> list[ExtractedIOC]:
        results = []
        skip = skip_domains or set()

        for match in DOMAIN_PATTERN.finditer(line):
            domain = match.group(1).lower()

            # Skip domains already captured as part of URLs
            if domain in skip:
                continue

            # Skip URL-encoded fragments (e.g. "2fwww.ionos.com" from %2F...)
            if domain[:2] in ("2f", "3a", "3d", "26", "3f"):
                continue
            # Also catch hex-encoded prefixes like "https3a2f2f..."
            if any(frag in domain for frag in ("3a2f", "2f2f")):
                continue

            # Use root-domain matching for benign check
            root = extract_root_domain(domain)
            if root in BENIGN_DOMAINS:
                continue
            if domain in JS_FALSE_DOMAINS:
                continue

            # Skip truncated benign domains from obfuscated/XOR'd content.
            # E.g. "ffice.com" is a broken fragment of "office.com".
            if any(bd.endswith(domain) and bd != domain for bd in BENIGN_DOMAINS):
                continue

            # Skip i18n / validation key patterns (vat-id.input.error.message.format-error.il)
            # These have 4+ labels and contain error/message/input segments
            labels = domain.split(".")
            if len(labels) >= 4 and any(
                seg in ("error", "message", "input", "required", "format")
                for seg in labels
            ):
                continue

            # Skip CSS class/state patterns (tbody.collapse.in, tr.show.no)
            css_state_labels = {
                "collapse", "toggle", "show", "hide", "fade", "active",
                "disabled", "visible", "invisible", "open", "closed",
                "expanded", "collapsed", "selected", "checked",
                "country-selector-dropdown",
            }
            if len(labels) >= 3 and any(
                seg in css_state_labels for seg in labels
            ):
                continue

            # Skip JS object property access patterns (this.br, caller.name, etc.)
            if any(domain.startswith(prefix) for prefix in _JS_OBJECT_PREFIXES):
                continue

            # Skip very short domains (likely false positives)
            if len(domain) < 5:
                continue
            # Must have at least one dot (SLD.TLD)
            if "." not in domain:
                continue
            tld = domain.rsplit(".", 1)[-1]
            # Skip if the "TLD" is actually a file extension
            if "." + tld in FALSE_DOMAIN_EXTENSIONS:
                continue
            # Only accept real TLDs
            if tld not in VALID_TLDS:
                continue
            # Require each label to be 2+ chars (filters w.com, a.net)
            labels = domain.split(".")
            if any(len(label) < 2 for label in labels):
                continue

            # Skip CSS class-like patterns that end in a valid TLD (e.g.
            # "wp-block-buttons.is", "spectrum-textfield--multiline.is")
            # Real domains rarely have double-hyphens or BEM-like naming
            if "--" in domain or (
                tld == "is" and "-" in labels[0] and len(labels) == 2
            ):
                continue

            # Skip JS-prone TLDs when the SLD looks like a variable name
            # (single label, no hyphens, not a known registrar pattern)
            if tld in _JS_PRONE_TLDS and len(labels) == 2:
                sld = labels[0]
                # Real domains usually aren't camelCase or pure lowercase
                # JS vars like "rootdiv", "errgroupobj", "functioncaller"
                if any(c.isupper() for c in sld[1:]):  # camelCase
                    continue
                # Very short unhyphenated SLD (≤3 chars) + JS-prone TLD is
                # overwhelmingly a minified JS property access: he.name,
                # ge.th, mt.host, bz.jp.  Real domains with such short SLDs
                # on these TLDs are rare enough to accept the miss.
                if len(sld) <= 3 and "-" not in sld:
                    continue
                # Very long single-word SLD + JS-prone TLD = likely JS var
                if len(sld) > 12 and "-" not in sld:
                    continue
                # .id TLD: single unhyphenated word is almost always a JS
                # property access (rootdiv.id, overlay.id, enduser.id).
                # Real Indonesian domains use hyphens or multi-label names.
                if tld == "id" and "-" not in sld:
                    continue

            confidence = 60
            line_lower = line.lower()
            if any(
                kw in line_lower
                for kw in ("host", "server", "smtp", "url", "send", "post", "gate")
            ):
                confidence = 80
            results.append(ExtractedIOC(
                type=IndicatorType.DOMAIN,
                value=domain,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=confidence,
            ))
        return results

    @staticmethod
    def _is_placeholder_phone(phone: str) -> bool:
        """Detect placeholder/test phone numbers."""
        digits = "".join(c for c in phone if c.isdigit())
        # Sequential digits (1234567890)
        if "1234567890" in digits or "0123456789" in digits:
            return True
        # US 555 numbers (reserved for fiction)
        if digits.startswith("1") and "555" in digits[1:5]:
            return True
        # All-same digit patterns (8888800000, 9999999999)
        unique_digits = set(digits[len(digits)//3:])  # check subscriber portion
        if len(unique_digits) <= 1:
            return True
        # Repeated zeros in subscriber (00 00 00, 000000)
        subscriber = digits[3:]  # skip country code
        return bool(subscriber and subscriber.replace("0", "") == "")

    def _extract_phone_numbers(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in PHONE_PATTERN.finditer(line):
            phone = match.group(0).strip()
            # Real international numbers are 9-13 digits (country + subscriber).
            # E.164 allows up to 15 but >13 is almost always JS/CSS garbage.
            # <9 is too short to be meaningful (most countries need 7+ subscriber).
            digit_count = sum(1 for c in phone if c.isdigit())
            if digit_count < 9 or digit_count > 13:
                continue
            if self._is_placeholder_phone(phone):
                continue
            results.append(ExtractedIOC(
                type=IndicatorType.PHONE_NUMBER,
                value=phone,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=65,
            ))
        return results

    def _extract_telegram_handles(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        # Require a Telegram-context marker on the same line — a bare
        # "@handle" match in isolation is overwhelmingly a JS decorator,
        # CSS at-rule, or minified symbol.  The marker requirement cuts
        # the bulk of the false-positive handles we were seeing out of
        # bot-detection.js, angular.min.js, and similar obfuscated JS.
        line_lower = line.lower()
        if not any(m in line_lower for m in TELEGRAM_CONTEXT_MARKERS):
            return []

        results = []
        seen: set[str] = set()
        for pattern in (TELEGRAM_HANDLE_PATTERN, TELEGRAM_URL_HANDLE_PATTERN):
            for match in pattern.finditer(line):
                handle = match.group(1).lower()
                if handle in TELEGRAM_HANDLE_EXCLUSIONS:
                    continue
                if len(handle) < 5:
                    continue
                if handle in seen:
                    continue
                seen.add(handle)
                results.append(ExtractedIOC(
                    type=IndicatorType.TELEGRAM_HANDLE,
                    value=f"@{handle}",
                    source_file=source_file,
                    line_number=line_num,
                    context=line[:200],
                    confidence=70,
                ))
        return results

    def _extract_aitm_indicators(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        """Detect AiTM proxy indicators — attacker domain referencing real auth endpoints."""
        if not self._source_root_domain:
            return []
        # Skip if the kit itself IS a legitimate auth domain
        if self._source_root_domain in {
            extract_root_domain(ep) for ep in AITM_AUTH_ENDPOINTS
        }:
            return []

        results = []
        line_lower = line.lower()
        for endpoint in AITM_AUTH_ENDPOINTS:
            if endpoint in line_lower:
                results.append(ExtractedIOC(
                    type=IndicatorType.C2_URL,
                    value=f"https://{endpoint}",
                    source_file=source_file,
                    line_number=line_num,
                    context=f"AiTM proxy: {self._source_root_domain} proxying {endpoint}",
                    confidence=90,
                ))
        return results

    def _deduplicate(self, iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
        seen: dict[tuple, ExtractedIOC] = {}
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())

    def extract_network_iocs_from_requests_json(
        self, requests_json_path: str,
    ) -> list[ExtractedIOC]:
        """Parse the browser-render network log and emit structured IOCs.

        ``requests.json`` is JSON, not free text, and carries per-request
        attribution (url, status, content_type, resource_type).  Parsing it
        structurally lets us classify each URL's origin and promote only
        attacker-or-unknown hosts to IOCs — third-party CDN/analytics noise
        gets dropped instead of being regex-scraped back in.
        """
        try:
            entries = json.loads(Path(requests_json_path).read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug("Failed to read %s: %s", requests_json_path, e)
            return []
        if not isinstance(entries, list):
            return []

        results: list[ExtractedIOC] = []
        seen_domains: set[str] = set()
        seen_c2_urls: set[str] = set()
        relative_source = "requests.json"

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                continue
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            hostname = (parsed.hostname or "").lower()
            if not hostname or "." not in hostname:
                continue
            if hostname in ("localhost", "127.0.0.1"):
                continue

            root = extract_root_domain(hostname)

            # Drop known-benign origins wholesale — we don't IOC a Cloudflare
            # analytics ping or a Microsoft auth CDN request.
            if root in BENIGN_URL_ROOT_DOMAINS:
                continue

            # Same-root as the lure is the phishing page itself; its domain
            # is already captured by SOURCE_URL / redirect-chain extraction
            # in analysis.extract_iocs.  Avoid double-booking.
            if (
                self._source_root_domain
                and root == self._source_root_domain
            ):
                continue

            # Domain IOC — unique per host, high confidence because this
            # came from a real connection the browser actually made.
            if hostname not in seen_domains:
                seen_domains.add(hostname)
                results.append(ExtractedIOC(
                    type=IndicatorType.DOMAIN,
                    value=hostname,
                    source_file=relative_source,
                    line_number=0,
                    context=f"browser_request:{url[:180]}",
                    confidence=85,
                ))

            # WebSockets and non-GET request methods are strong exfil signals.
            method = entry.get("method") or ""
            resource_type = entry.get("resource_type") or ""
            is_websocket = (
                resource_type.lower() == "websocket"
                or url.lower().startswith(("ws://", "wss://"))
            )
            is_exfil_method = method.upper() in {"POST", "PUT", "PATCH"}

            if (is_websocket or is_exfil_method) and url not in seen_c2_urls:
                seen_c2_urls.add(url)
                results.append(ExtractedIOC(
                    type=IndicatorType.C2_URL,
                    value=url,
                    source_file=relative_source,
                    line_number=0,
                    context=(
                        f"browser_{'websocket' if is_websocket else method.lower()}"
                    ),
                    confidence=90 if is_websocket else 80,
                ))

        return results
