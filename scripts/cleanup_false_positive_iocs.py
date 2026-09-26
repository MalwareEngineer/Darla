#!/usr/bin/env python3
"""One-time cleanup of false positive IOCs from the indicators table.

Run after deploying the improved IOC extraction patterns.
Safe to run multiple times — deletes are idempotent.

Usage:
    # Dry run (default) — shows what would be deleted
    python scripts/cleanup_false_positive_iocs.py

    # Actually delete
    python scripts/cleanup_false_positive_iocs.py --execute
"""

import argparse
import sys

from sqlalchemy import text

from darla.database import get_sync_db

# Benign root domain patterns for C2 URLs
C2_URL_BENIGN_PATTERNS = [
    # Google ecosystem
    "%google.com%", "%googleapis%", "%gstatic%", "%googleusercontent%",
    "%googlesyndication%", "%googletagmanager%", "%google-analytics%",
    "%doubleclick%", "%withgoogle%", "%ggpht%", "%googlevideo%",
    "%googleadservices%",
    # Microsoft
    "%microsoft.com%", "%microsoftonline%", "%windows.net%",
    "%azureedge.net%", "%office.com%", "%office365%",
    "%live.com%", "%outlook.com%", "%bing.com%",
    # Amazon / CDNs
    "%amazonaws.com%", "%cloudfront.net%", "%awsstatic%",
    "%cloudflare.com%", "%jsdelivr.net%", "%unpkg.com%",
    "%akamai%", "%fastly%", "%bootstrapcdn%", "%stackpath%",
    "%cdnjs%",
    # Libraries / frameworks
    "%jquery.com%", "%tailwindcss%", "%fontawesome%",
    "%getbootstrap%",
    # Site builders
    "%weebly%", "%wix.com%", "%wixsite%", "%parastorage%",
    "%strikingly%", "%mystrikingly%", "%squarespace%",
    "%wordpress.com%", "%wordpress.org%", "%wp.com%",
    "%shopify%",
    # Code hosting / docs
    "%github.com%", "%github.io%", "%githubusercontent%",
    "%githubassets%", "%gitlab%", "%gitbook%",
    # Social media
    "%facebook.com%", "%fbcdn%", "%twitter.com%", "%twimg%",
    "%instagram.com%", "%linkedin.com%", "%youtube.com%",
    "%vimeo.com%", "%tiktok%", "%reddit.com%", "%pinterest%",
    # SaaS
    "%zoom.us%", "%calendly.com%", "%jotform%", "%jotfor.ms%",
    "%typeform%", "%slack.com%", "%notion.so%",
    "%atlassian%", "%hubspot%", "%zendesk%", "%intercom%",
    # Gaming platforms
    "%roblox.com%", "%rbxcdn%", "%steampowered%", "%steamstatic%",
    # Email providers
    "%yahoo.com%", "%yimg%", "%protonmail%", "%proton.me%",
    # Payment / finance
    "%paypal.com%", "%paypalobjects%", "%stripe.com%",
    # Cloud storage
    "%dropbox.com%", "%onedrive.com%",
    # Apple
    "%apple.com%", "%icloud.com%", "%mzstatic%",
    # Standards / reference
    "%w3.org%", "%w3schools%", "%schema.org%",
    "%php.net%", "%apache.org%", "%mozilla.org%",
    "%stackoverflow%", "%npmjs.com%",
    # Captcha / analytics
    "%recaptcha%", "%hcaptcha%",
    "%segment.io%", "%mixpanel%", "%amplitude%", "%newrelic%",
    # Affiliate / misc
    "%pxf.io%", "%shareasale%", "%archive.org%",
    "%pearltrees%", "%tistory.com%",
    "%qr-code-generator%",
    "%sentry.io%", "%cloudinary%",
    "%gravatar.com%",
]

# Patterns for static asset URLs that slipped through
C2_URL_ASSET_PATTERNS = [
    "%.js?%", "%.css?%",  # query-string bypassed old suffix check
    "%.woff%", "%.woff2%", "%.ttf%", "%.eot%",
    "%.png", "%.jpg", "%.jpeg", "%.gif", "%.svg", "%.ico",
    "%.webp", "%.map",
]

# Domain false positive patterns
DOMAIN_BENIGN_PATTERNS = [
    # Truncated URL fragments (missing leading chars)
    "ww.%", "ocs.%", "eet.%", "rive.%", "orkspace.%",
    "tatic.%", "olicy.%", "pp.%", "ec.%", "sl.%", "h3.%",
    "nt.%", "omepage%",
    # URL-encoded fragments
    "2f%", "3a%", "3d%", "26%", "https3a%",
    # JS property access
    "window.%", "document.%", "object.%", "x22object.%",
    "navigator.%", "location.%", "element.%", "event.%",
    "el-descriptions%", "locale-dataset%",
    "link.%click",
]

# Add the same root domain patterns for domains
DOMAIN_ROOT_BENIGN_PATTERNS = [
    "%google.com", "%googleapis.com", "%gstatic.com",
    "%googleusercontent.com",
    "%roblox.com", "%rbxcdn.com",
    "%weebly.com", "%weeblysite.com",
    "%wix.com", "%wixsite.com", "%parastorage.com",
    "%facebook.com", "%twitter.com", "%instagram.com",
    "%linkedin.com", "%youtube.com", "%vimeo.com",
    "%github.com", "%github.io", "%githubusercontent.com",
    "%gitbook.io",
    "%zoom.us", "%jotform.com",
    "%apple.com", "%icloud.com",
    "%microsoft.com", "%outlook.com", "%live.com",
    "%hotmail.com", "%yahoo.com",
    "%wordpress.com", "%wordpress.org",
    "%amazon.com", "%amazonaws.com",
    "%cloudfront.net", "%cloudflare.com",
    "%bootstrapcdn.com", "%jsdelivr.net",
    "%stackoverflow.com", "%mozilla.org",
    "%apache.org", "%php.net", "%w3.org",
    "%paypal.com", "%stripe.com",
    "%dropbox.com",
    "%slack.com", "%notion.so",
    "%hubspot%", "%zendesk%",
    "%tistory.com",
    "%qr-code-generator.com",
]


def build_delete_query(
    indicator_type: str,
    like_patterns: list[str],
) -> tuple[str, dict]:
    """Build a parameterized DELETE query with LIKE conditions."""
    conditions = []
    params = {}
    for i, pattern in enumerate(like_patterns):
        param_name = f"p{i}"
        conditions.append(f"value LIKE :{param_name}")
        params[param_name] = pattern

    where_clause = " OR ".join(conditions)
    query = f"DELETE FROM indicators WHERE type = :ioc_type AND ({where_clause})"
    params["ioc_type"] = indicator_type
    return query, params


def build_count_query(
    indicator_type: str,
    like_patterns: list[str],
) -> tuple[str, dict]:
    """Build a parameterized COUNT query with LIKE conditions."""
    conditions = []
    params = {}
    for i, pattern in enumerate(like_patterns):
        param_name = f"p{i}"
        conditions.append(f"value LIKE :{param_name}")
        params[param_name] = pattern

    where_clause = " OR ".join(conditions)
    query = f"SELECT count(*) FROM indicators WHERE type = :ioc_type AND ({where_clause})"
    params["ioc_type"] = indicator_type
    return query, params


def count_matching(db, indicator_type: str, patterns: list[str]) -> int:
    """Count indicators matching any of the given patterns."""
    if not patterns:
        return 0
    query, params = build_count_query(indicator_type, patterns)
    result = db.execute(text(query), params)
    return result.scalar()


def delete_matching(db, indicator_type: str, patterns: list[str]) -> int:
    """Delete indicators matching any of the given patterns. Returns count."""
    if not patterns:
        return 0
    query, params = build_delete_query(indicator_type, patterns)
    result = db.execute(text(query), params)
    return result.rowcount


def cleanup_trailing_junk(db, execute: bool) -> int:
    """Delete C2 URLs with trailing syntax junk."""
    query = r"""
        SELECT count(*) FROM indicators
        WHERE type = 'C2_URL'
        AND value ~ '[''";,)\]}>\\]+$'
    """
    count = db.execute(text(query)).scalar()
    if execute and count > 0:
        delete_q = r"""
            DELETE FROM indicators
            WHERE type = 'C2_URL'
            AND value ~ '[''";,)\]}>\\]+$'
        """
        db.execute(text(delete_q))
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Clean up false positive IOCs from the indicators table."
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete records (default is dry run)",
    )
    args = parser.parse_args()

    db = get_sync_db()

    try:
        # Get totals before cleanup
        total_c2 = db.execute(
            text("SELECT count(*) FROM indicators WHERE type = 'C2_URL'")
        ).scalar()
        total_domain = db.execute(
            text("SELECT count(*) FROM indicators WHERE type = 'DOMAIN'")
        ).scalar()

        print(f"Current totals: C2_URL={total_c2:,}  DOMAIN={total_domain:,}")
        print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN'}")
        print()

        # --- C2 URLs ---
        c2_benign = count_matching(db, "C2_URL", C2_URL_BENIGN_PATTERNS)
        c2_assets = count_matching(db, "C2_URL", C2_URL_ASSET_PATTERNS)
        c2_junk = cleanup_trailing_junk(db, execute=False)

        print("C2_URL cleanup:")
        print(f"  Benign service domains:  {c2_benign:>8,}")
        print(f"  Static asset URLs:       {c2_assets:>8,}")
        print(f"  Trailing syntax junk:    {c2_junk:>8,}")
        c2_total_remove = c2_benign + c2_assets + c2_junk
        print(f"  Total to remove:         {c2_total_remove:>8,} / {total_c2:,} ({100*c2_total_remove/max(total_c2,1):.0f}%)")
        print()

        # --- Domains ---
        dom_benign = count_matching(db, "DOMAIN", DOMAIN_BENIGN_PATTERNS)
        dom_root = count_matching(db, "DOMAIN", DOMAIN_ROOT_BENIGN_PATTERNS)

        print("DOMAIN cleanup:")
        print(f"  Truncated/encoded/JS:    {dom_benign:>8,}")
        print(f"  Benign root domains:     {dom_root:>8,}")
        dom_total_remove = dom_benign + dom_root
        print(f"  Total to remove:         {dom_total_remove:>8,} / {total_domain:,} ({100*dom_total_remove/max(total_domain,1):.0f}%)")
        print()

        if not args.execute:
            print("Dry run complete. Use --execute to actually delete.")
            return

        # Execute deletions
        print("Executing deletions...")

        deleted = 0
        deleted += delete_matching(db, "C2_URL", C2_URL_BENIGN_PATTERNS)
        deleted += delete_matching(db, "C2_URL", C2_URL_ASSET_PATTERNS)
        deleted += cleanup_trailing_junk(db, execute=True)
        deleted += delete_matching(db, "DOMAIN", DOMAIN_BENIGN_PATTERNS)
        deleted += delete_matching(db, "DOMAIN", DOMAIN_ROOT_BENIGN_PATTERNS)

        db.commit()

        # Get new totals
        new_c2 = db.execute(
            text("SELECT count(*) FROM indicators WHERE type = 'C2_URL'")
        ).scalar()
        new_domain = db.execute(
            text("SELECT count(*) FROM indicators WHERE type = 'DOMAIN'")
        ).scalar()

        print(f"\nDeleted {deleted:,} false positive IOCs.")
        print(f"New totals: C2_URL={new_c2:,}  DOMAIN={new_domain:,}")
        print(f"Reduction:  C2_URL {total_c2:,} -> {new_c2:,}  DOMAIN {total_domain:,} -> {new_domain:,}")

    except Exception as e:
        db.rollback()
        print(f"Error: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
