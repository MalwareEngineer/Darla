#!/usr/bin/env python3
"""Purge all Phishing.Database and URLhaus data from the database.

Deletes in FK-safe order with batched deletes to avoid long-running locks.
Run INSIDE the darla-postgres container or with DATABASE_URL set.

Usage:
    docker exec darla-worker-beat python scripts/drop_phishing_database_urlhaus.py
"""

import os

import psycopg2

BATCH_SIZE = 10_000
SOURCES = ("PHISHING_DATABASE", "URLHAUS")

DSN = os.environ.get(
    "PK_SYNC_DATABASE_URL",
    "postgresql+psycopg2://darla:darla@postgres:5432/darla",
).replace("postgresql+psycopg2://", "postgresql://")


def batch_delete(cur, label: str, sql: str) -> int:
    """Execute DELETE in batches, return total deleted."""
    total = 0
    while True:
        cur.execute(sql)
        deleted = cur.rowcount
        total += deleted
        cur.connection.commit()
        if deleted == 0:
            break
        print(f"  {label}: deleted {total:,} so far…")
    print(f"  {label}: {total:,} total rows deleted.")
    return total


def main():
    print("Connecting to database…")
    conn = psycopg2.connect(DSN)
    conn.autocommit = False
    cur = conn.cursor()

    # Step 0: Count what we're about to delete
    for table in ("feed_entries", "kits", "indicators", "analysis_results"):
        if table == "feed_entries":
            cur.execute(
                "SELECT COUNT(*) FROM feed_entries WHERE source IN %s", (SOURCES,)
            )
        elif table == "kits":
            cur.execute(
                "SELECT COUNT(*) FROM kits WHERE feed_entry_id IN "
                "(SELECT id FROM feed_entries WHERE source IN %s)", (SOURCES,)
            )
        elif table == "indicators":
            cur.execute(
                "SELECT COUNT(*) FROM indicators WHERE kit_id IN "
                "(SELECT id FROM kits WHERE feed_entry_id IN "
                "(SELECT id FROM feed_entries WHERE source IN %s))", (SOURCES,)
            )
        elif table == "analysis_results":
            cur.execute(
                "SELECT COUNT(*) FROM analysis_results WHERE kit_id IN "
                "(SELECT id FROM kits WHERE feed_entry_id IN "
                "(SELECT id FROM feed_entries WHERE source IN %s))", (SOURCES,)
            )
        count = cur.fetchone()[0]
        print(f"  {table}: {count:,} rows to delete")
    conn.commit()

    print("\nPurging Phishing.Database and URLhaus data…\n")

    # Step 1: indicators
    batch_delete(cur, "indicators", f"""
        DELETE FROM indicators WHERE id IN (
            SELECT i.id FROM indicators i
            JOIN kits k ON k.id = i.kit_id
            JOIN feed_entries fe ON fe.id = k.feed_entry_id
            WHERE fe.source IN {SOURCES!r}
            LIMIT {BATCH_SIZE}
        )
    """)

    # Step 2: analysis_results
    batch_delete(cur, "analysis_results", f"""
        DELETE FROM analysis_results WHERE id IN (
            SELECT ar.id FROM analysis_results ar
            JOIN kits k ON k.id = ar.kit_id
            JOIN feed_entries fe ON fe.id = k.feed_entry_id
            WHERE fe.source IN {SOURCES!r}
            LIMIT {BATCH_SIZE}
        )
    """)

    # Step 3: campaign_kits
    batch_delete(cur, "campaign_kits", f"""
        DELETE FROM campaign_kits WHERE kit_id IN (
            SELECT k.id FROM kits k
            JOIN feed_entries fe ON fe.id = k.feed_entry_id
            WHERE fe.source IN {SOURCES!r}
            LIMIT {BATCH_SIZE}
        )
    """)

    # Step 4: kits
    batch_delete(cur, "kits", f"""
        DELETE FROM kits WHERE id IN (
            SELECT k.id FROM kits k
            JOIN feed_entries fe ON fe.id = k.feed_entry_id
            WHERE fe.source IN {SOURCES!r}
            LIMIT {BATCH_SIZE}
        )
    """)

    # Step 5: feed_entries
    batch_delete(cur, "feed_entries", f"""
        DELETE FROM feed_entries WHERE id IN (
            SELECT id FROM feed_entries
            WHERE source IN {SOURCES!r}
            LIMIT {BATCH_SIZE}
        )
    """)

    # Step 6: VACUUM
    print("\nRunning VACUUM ANALYZE…")
    conn.autocommit = True
    for table in ("indicators", "analysis_results", "campaign_kits", "kits", "feed_entries"):
        cur.execute(f"VACUUM ANALYZE {table}")
        print(f"  VACUUM ANALYZE {table} done.")

    cur.close()
    conn.close()
    print("\nDone. Phishing.Database and URLhaus data purged.")


if __name__ == "__main__":
    main()
