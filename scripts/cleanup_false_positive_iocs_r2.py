#!/usr/bin/env python3
"""Round 2 cleanup of false positive IOCs from the indicators table.

Targets patterns missed by the first cleanup + new patterns found
after the kit discovery crawling went live.

Usage:
    # Dry run (default) -- shows what would be deleted
    python scripts/cleanup_false_positive_iocs_r2.py

    # Actually delete
    python scripts/cleanup_false_positive_iocs_r2.py --execute
"""

import argparse
import sys

from sqlalchemy import text

from darla.database import get_sync_db

# ---- C2 URL false positives ----

# New benign service domains missed in round 1
C2_URL_NEW_BENIGN = [
    # Blogging / CMS
    "%blogger.com%", "%blogspot.com%",
    # Travel / booking
    "%booking.com%", "%bstatic.com%",
    # URL shorteners
    "%bitly.com%", "%bit.ly%",
    "%l.ead.me%",
    # Security vendors
    "%fortinet.com%",
    # Cookie / consent
    "%cookielaw.org%", "%onetrust.com%",
    # Monitoring
    "%datadoghq%",
    # SaaS / link pages
    "%flowcode.com%", "%campsite.bio%", "%campsite.to%",
    # Website builders
    "%webador.com%",
    "%wixpress.com%",
    # Standards / reference
    "%json-schema.org%", "%quirksmode.org%",
    # Social / gaming
    "%twitch.tv%", "%twitchcdn%",
    # CDN / misc
    "%dropboxstatic.com%",
    "%offset.com%",
    "%edgecastcdn.net%",
    "%vk-portal.net%",
    "%latofonts.com%",
    "%shopifyanalytics%",
]

# URLs with HTML-entity-corrupted hostnames (e.g. google.com&quot)
C2_URL_HTML_ENTITY_PATTERNS = [
    "%&quot%",
    "%&amp%",
    "%&#39%",
    "%&lt%",
    "%&gt%",
]

# javascript: pseudo-protocol
C2_URL_JS_PSEUDO = [
    "https://javascript:%",
    "http://javascript:%",
]

# base64 blobs in URL
C2_URL_BASE64 = [
    "%==%",
]


# ---- DOMAIN false positives ----

# JS object property access patterns
DOMAIN_JS_OBJECT_PATTERNS = [
    "this.%", "self.%",
    "window.%", "document.%",
    "navigator.%", "element.%",
    "event.%", "error.%",
    "screen.%", "history.%",
    "location.%", "parent.%",
    "caller.%", "button.%",
    "input.%", "form.%",
    "link.%", "file.%",
    "cookie.%", "entry.%",
    "source.%", "asset.%",
    "media.%", "place.%",
    "attr.%", "attribute.%",
    "item.%", "data.%",
    "browser.%",
]

# URL-encoded JS fragments that still slip through
DOMAIN_URLENCODED_JS = [
    "u003d%.at", "u003d%.ml", "u003d%.es",
    "u003d%.br", "u003d%.pt", "u003d%.au",
    "u003d%.in", "u003d%.my", "u003d%.ph",
    "u0026%.lt", "u0026%.ph", "u0026%.at",
    "u003dl.%", "u003dg.%", "u003dt.%",
    "u003dd.%", "u003dz.%",
]

# Specific observed FPs
DOMAIN_SPECIFIC_FPS = [
    "rootdiv.id",
    "linkel.media",
    "thirdparty.is",
    "glimitedaccount.com",
    "functioncaller.name",
    "errgroupobj.name",
    "syntaxerror.name",
    "tokeninput.name",
    "opensharecontrolparams.item.name",
    "registerbutton.name",
    "radiobutton.name",
    "addialog.name",
    "tokeninfo.name",
    "eventvenue.name",
    "blogspot.com",
]

# New benign root domains for DOMAIN type
DOMAIN_NEW_BENIGN = [
    "%blogger.com",
    "%blogspot.com",
    "%booking.com",
    "%bstatic.com",
    "%bitly.com",
    "%fortinet.com",
    "%cookielaw.org",
    "%datadoghq%",
    "%flowcode.com",
    "%webador.com",
    "%wixpress.com",
    "%twitch.tv",
    "%dropboxstatic.com",
    "%edgecastcdn.net",
    "%vk-portal.net",
    "%offset.com",
    "%json-schema.org",
    "%quirksmode.org",
    "%latofonts.com",
]

# ---- EMAIL false positives ----
# Sentry DSN emails (uuid@*.sentry.io, uuid@*.wixpress.com)
EMAIL_FP_PATTERNS = [
    "%@%.sentry.io",
    "%@sentry.io",
    "%@%.wixpress.com",
    "%@sentry-next.wixpress.com",
    "%@%.ingest.sentry.io",
    "%@%.ingest.us.sentry.io",
    "%@d.dropbox.com",
]


def count_matching(db, indicator_type: str, patterns: list[str]) -> int:
    if not patterns:
        return 0
    conditions = []
    params = {"ioc_type": indicator_type}
    for i, pattern in enumerate(patterns):
        conditions.append(f"value LIKE :p{i}")
        params[f"p{i}"] = pattern
    query = f"SELECT count(*) FROM indicators WHERE type = :ioc_type AND ({' OR '.join(conditions)})"
    return db.execute(text(query), params).scalar()


def count_exact(db, indicator_type: str, values: list[str]) -> int:
    if not values:
        return 0
    conditions = []
    params = {"ioc_type": indicator_type}
    for i, val in enumerate(values):
        conditions.append(f"value = :v{i}")
        params[f"v{i}"] = val
    query = f"SELECT count(*) FROM indicators WHERE type = :ioc_type AND ({' OR '.join(conditions)})"
    return db.execute(text(query), params).scalar()


def delete_matching(db, indicator_type: str, patterns: list[str]) -> int:
    if not patterns:
        return 0
    conditions = []
    params = {"ioc_type": indicator_type}
    for i, pattern in enumerate(patterns):
        conditions.append(f"value LIKE :p{i}")
        params[f"p{i}"] = pattern
    query = f"DELETE FROM indicators WHERE type = :ioc_type AND ({' OR '.join(conditions)})"
    return db.execute(text(query), params).rowcount


def delete_exact(db, indicator_type: str, values: list[str]) -> int:
    if not values:
        return 0
    conditions = []
    params = {"ioc_type": indicator_type}
    for i, val in enumerate(values):
        conditions.append(f"value = :v{i}")
        params[f"v{i}"] = val
    query = f"DELETE FROM indicators WHERE type = :ioc_type AND ({' OR '.join(conditions)})"
    return db.execute(text(query), params).rowcount


def main():
    parser = argparse.ArgumentParser(
        description="Round 2 cleanup of false positive IOCs."
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Actually delete (default is dry run)",
    )
    args = parser.parse_args()

    db = get_sync_db()

    try:
        # Current totals
        totals = {}
        for t in ("C2_URL", "DOMAIN", "EMAIL"):
            totals[t] = db.execute(
                text("SELECT count(*) FROM indicators WHERE type = :t"),
                {"t": t},
            ).scalar()

        print(f"Current totals: C2_URL={totals['C2_URL']:,}  DOMAIN={totals['DOMAIN']:,}  EMAIL={totals['EMAIL']:,}")
        print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN'}")
        print()

        # ---- C2_URL ----
        c2_benign = count_matching(db, "C2_URL", C2_URL_NEW_BENIGN)
        c2_entity = count_matching(db, "C2_URL", C2_URL_HTML_ENTITY_PATTERNS)
        c2_js = count_matching(db, "C2_URL", C2_URL_JS_PSEUDO)
        c2_b64 = count_matching(db, "C2_URL", C2_URL_BASE64)
        c2_total = c2_benign + c2_entity + c2_js + c2_b64

        print("C2_URL cleanup:")
        print(f"  New benign domains:      {c2_benign:>8,}")
        print(f"  HTML-entity hostnames:   {c2_entity:>8,}")
        print(f"  javascript: pseudo-URLs: {c2_js:>8,}")
        print(f"  base64-in-URL:           {c2_b64:>8,}")
        print(f"  Total to remove:         {c2_total:>8,} / {totals['C2_URL']:,}")
        print()

        # ---- DOMAIN ----
        dom_js = count_matching(db, "DOMAIN", DOMAIN_JS_OBJECT_PATTERNS)
        dom_enc = count_matching(db, "DOMAIN", DOMAIN_URLENCODED_JS)
        dom_specific = count_exact(db, "DOMAIN", DOMAIN_SPECIFIC_FPS)
        dom_benign = count_matching(db, "DOMAIN", DOMAIN_NEW_BENIGN)
        dom_total = dom_js + dom_enc + dom_specific + dom_benign

        print("DOMAIN cleanup:")
        print(f"  JS object patterns:      {dom_js:>8,}")
        print(f"  URL-encoded JS:          {dom_enc:>8,}")
        print(f"  Specific known FPs:      {dom_specific:>8,}")
        print(f"  New benign domains:      {dom_benign:>8,}")
        print(f"  Total to remove:         {dom_total:>8,} / {totals['DOMAIN']:,}")
        print()

        # ---- EMAIL ----
        email_fp = count_matching(db, "EMAIL", EMAIL_FP_PATTERNS)
        print("EMAIL cleanup:")
        print(f"  Sentry DSN / internal:   {email_fp:>8,}")
        print(f"  Total to remove:         {email_fp:>8,} / {totals['EMAIL']:,}")
        print()

        grand_total = c2_total + dom_total + email_fp
        print(f"Grand total to remove:     {grand_total:>8,}")
        print()

        if not args.execute:
            print("Dry run complete. Use --execute to actually delete.")
            return

        print("Executing deletions...")
        deleted = 0
        deleted += delete_matching(db, "C2_URL", C2_URL_NEW_BENIGN)
        deleted += delete_matching(db, "C2_URL", C2_URL_HTML_ENTITY_PATTERNS)
        deleted += delete_matching(db, "C2_URL", C2_URL_JS_PSEUDO)
        deleted += delete_matching(db, "C2_URL", C2_URL_BASE64)
        deleted += delete_matching(db, "DOMAIN", DOMAIN_JS_OBJECT_PATTERNS)
        deleted += delete_matching(db, "DOMAIN", DOMAIN_URLENCODED_JS)
        deleted += delete_exact(db, "DOMAIN", DOMAIN_SPECIFIC_FPS)
        deleted += delete_matching(db, "DOMAIN", DOMAIN_NEW_BENIGN)
        deleted += delete_matching(db, "EMAIL", EMAIL_FP_PATTERNS)
        db.commit()

        # New totals
        for t in ("C2_URL", "DOMAIN", "EMAIL"):
            new = db.execute(
                text("SELECT count(*) FROM indicators WHERE type = :t"),
                {"t": t},
            ).scalar()
            print(f"  {t}: {totals[t]:,} -> {new:,}")

        print(f"\nDeleted {deleted:,} false positive IOCs total.")

    except Exception as e:
        db.rollback()
        print(f"Error: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
