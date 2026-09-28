"""HTTP client utilities for downloading kits and fetching feeds."""

import json
import logging
import random
from pathlib import Path

import httpx
import redis

from darla.config import get_settings
from darla.private_config import load_user_agents
from darla.utils.egress import (
    egress_block_reason,
    guarded_async_transport,
    guarded_transport,
)

logger = logging.getLogger(__name__)


def _random_headers() -> dict[str, str]:
    """Return headers mimicking a real browser request."""
    return {
        "User-Agent": random.choice(load_user_agents()),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def get_sync_client(**kwargs) -> httpx.Client:
    """Get a configured sync HTTP client for use in Celery tasks.

    Connections go through the egress guard (darla.utils.egress): only
    public addresses, checked at connect time on every redirect hop.
    """
    settings = get_settings()
    defaults = {
        "headers": _random_headers(),
        "timeout": settings.download_timeout,
        "follow_redirects": True,
        "transport": guarded_transport(),
    }
    defaults.update(kwargs)
    return httpx.Client(**defaults)


def fetch_with_cache(
    url: str, *, timeout: int = 120, headers: dict | None = None,
) -> httpx.Response | None:
    """Fetch a URL with ETag/If-Modified-Since caching via Redis.

    Returns the response on 200, or None on 304 Not Modified (caller should
    skip ingestion). Falls back to unconditional GET if Redis is unavailable.
    """
    settings = get_settings()
    cache_key = f"feed_cache:{url}"
    conditional_headers: dict[str, str] = {}

    # Try to load cached ETag/Last-Modified from Redis
    try:
        r = redis.from_url(settings.redis_url)
        cached = r.get(cache_key)
        if cached:
            meta = json.loads(cached)
            if meta.get("etag"):
                conditional_headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                conditional_headers["If-Modified-Since"] = meta["last_modified"]
    except Exception:
        logger.debug("Redis unavailable for feed cache, using unconditional GET")

    # Merge conditional headers with any caller-supplied headers
    merged_headers = {**(headers or {}), **conditional_headers}

    with get_sync_client(timeout=timeout) as client:
        response = client.get(url, headers=merged_headers)

    if response.status_code == 304:
        logger.info("Feed %s: 304 Not Modified, skipping ingestion", url[:80])
        return None

    response.raise_for_status()

    # Cache the response's ETag/Last-Modified for next time
    try:
        meta = {
            "etag": response.headers.get("etag"),
            "last_modified": response.headers.get("last-modified"),
        }
        r = redis.from_url(settings.redis_url)
        r.setex(cache_key, 86400, json.dumps(meta))
    except Exception:
        logger.debug("Failed to cache feed headers in Redis for %s", url[:80])

    return response


async def get_async_client(**kwargs) -> httpx.AsyncClient:
    """Get a configured async HTTP client (egress-guarded, like the sync one)."""
    settings = get_settings()
    defaults = {
        "headers": _random_headers(),
        "timeout": settings.download_timeout,
        "follow_redirects": True,
        "transport": guarded_async_transport(),
    }
    defaults.update(kwargs)
    return httpx.AsyncClient(**defaults)


def download_file(
    url: str, dest_dir: str, max_size_mb: int = 50,
) -> tuple[Path | None, str]:
    """Download a file from URL to dest_dir.

    Returns (filepath, reason) — filepath is None on failure,
    reason is "ok" on success or a short error description.
    Streams the download to enforce size limits without loading into memory.
    """
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)
    max_bytes = max_size_mb * 1024 * 1024

    try:
        with get_sync_client() as client, client.stream("GET", url) as response:
            response.raise_for_status()

            # Determine filename from URL or Content-Disposition
            filename = _extract_filename(url, response)
            filepath = dest_path / filename

            total = 0
            with open(filepath, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=8192):
                    total += len(chunk)
                    if total > max_bytes:
                        logger.warning(
                            "Download exceeded size limit (%d MB): %s",
                            max_size_mb,
                            url,
                        )
                        filepath.unlink(missing_ok=True)
                        return None, f"Exceeded size limit ({max_size_mb} MB)"

                    f.write(chunk)

            logger.info("Downloaded %s (%d bytes) to %s", url, total, filepath)
            return filepath, "ok"

    except httpx.HTTPStatusError as e:
        logger.error("HTTP error downloading %s: %s", url, e.response.status_code)
        return None, f"HTTP {e.response.status_code}"
    except httpx.TimeoutException as e:
        logger.error("Timeout downloading %s: %s", url, e)
        return None, "Connection timed out"
    except httpx.RequestError as e:
        if blocked := egress_block_reason(e):
            logger.warning("Blocked download of %s: %s", url, blocked)
            return None, blocked
        logger.error("Request error downloading %s: %s", url, e)
        return None, f"Request error: {type(e).__name__}"
    except Exception as e:
        logger.error("Unexpected error downloading %s: %s", url, e)
        return None, f"Unexpected error: {type(e).__name__}"


def _extract_filename(url: str, response: httpx.Response) -> str:
    """Extract a safe filename from URL or Content-Disposition header."""
    # Try Content-Disposition
    cd = response.headers.get("content-disposition", "")
    if "filename=" in cd:
        parts = cd.split("filename=")
        if len(parts) > 1:
            name = parts[1].strip('" ')
            if name:
                return _sanitize_filename(name)

    # Fall back to URL path
    from urllib.parse import urlparse

    path = urlparse(url).path
    name = path.split("/")[-1] if "/" in path else "download"
    return _sanitize_filename(name) if name else "download.bin"


def _sanitize_filename(name: str) -> str:
    """Remove dangerous characters from a filename."""
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(c if c in keep else "_" for c in name)[:255] or "download.bin"
