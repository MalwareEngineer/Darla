"""VictimService observation behavior — the central rule that gates
PhishPrint Victim creation by the monitored-domain allowlist while
preserving every observed email as an Indicator at the call site.

The tests here cover the **sync** observation hook
(``observe_victim_email``) used from Celery tasks.  The async CRUD
surface is exercised end-to-end through the API layer in a separate
file.

Key invariants under test:

  * non-monitored-domain emails NEVER produce a Victim row (caller
    is responsible for the Indicator emission — that's verified at
    the integration layer)
  * monitored-domain emails create exactly one Victim per unique
    address, even across multiple observations
  * multiple observations of the same victim from the same kit but
    different sources produce separate junction rows (so the source-
    channel breakdown on the per-victim page is accurate)
  * idempotency on ``(kit_id, victim_id, source)`` — chain redelivery
    must not produce duplicate observations
  * suffix-aware domain matching (``acme.com`` covers
    ``user@sub.acme.com``)
  * service-account auto-classification fires only on unambiguous
    cases
  * first/last_seen drift correctly across observation timestamps
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from darla.models import (
    Base,
    Kit,
    KitStatus,
    KitVictim,
    MonitoredDomain,
    Victim,
    VictimObservationSource,
    VictimType,
)
from darla.services.victim_service import (
    classify_email_type,
    observe_victim_email,
)

# ---------------------------------------------------------------------------
# In-process SQLite harness — the observation logic is pure ORM (no
# Postgres-specific features in this code path) so an in-memory
# SQLite gives us a fast, hermetic harness.  The model uses
# ``ondelete="CASCADE"`` on kit_victims FKs but we never delete the
# parent in these tests, so SQLite's looser FK semantics don't
# matter.
# ---------------------------------------------------------------------------

@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    # SQLite doesn't ship the postgres-specific UUID/JSONB columns
    # used elsewhere in the schema — but the only tables we exercise
    # in this test are the new ones plus a thin Kit row, all of which
    # SQLAlchemy will translate to portable column types when we
    # create_all on a fresh sqlite engine.
    Base.metadata.create_all(engine, tables=[
        Kit.__table__,
        MonitoredDomain.__table__,
        Victim.__table__,
        KitVictim.__table__,
    ])
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


def _make_kit(db: Session) -> Kit:
    """Insert a minimal Kit row — only fields needed for the
    observe_victim_email FK check + commit."""
    kit = Kit(
        id=uuid.uuid4(),
        source_url="https://example.com/lure",
        status=KitStatus.DOWNLOADED,
        chain_depth=0,
    )
    db.add(kit)
    db.flush()
    return kit


def _add_monitored(db: Session, *domains: str) -> None:
    for d in domains:
        db.add(MonitoredDomain(domain=d.lower()))
    db.flush()


# ---------------------------------------------------------------------------
# classify_email_type — auto-detection rules
# ---------------------------------------------------------------------------

def test_classify_noreply_is_service() -> None:
    """The textbook automated-mailer pattern — must always classify
    as service so operators don't have to triage."""
    assert classify_email_type("noreply@acme.com") == VictimType.SERVICE
    assert classify_email_type("no-reply@acme.com") == VictimType.SERVICE
    assert classify_email_type("donotreply@acme.com") == VictimType.SERVICE
    assert classify_email_type("do-not-reply@acme.com") == VictimType.SERVICE


def test_classify_postmaster_and_mailer_daemon_are_service() -> None:
    """RFC-mandated mailbox names that almost always represent
    automation, never an individual employee."""
    assert classify_email_type("postmaster@acme.com") == VictimType.SERVICE
    assert classify_email_type("mailer-daemon@acme.com") == VictimType.SERVICE


def test_classify_prefix_match_for_noreply_variants() -> None:
    """Real-world variants like ``noreply-billing@``, ``noreply2@``
    — prefix match catches them all without needing to enumerate."""
    assert classify_email_type("noreply-billing@acme.com") == VictimType.SERVICE
    assert classify_email_type("noreply2@acme.com") == VictimType.SERVICE


def test_classify_normal_user_defaults_to_user() -> None:
    """Conservative default — exec/distro/shared_mailbox need org
    context the pipeline doesn't have, so they're operator-tagged
    rather than auto-classified."""
    assert classify_email_type("john.doe@acme.com") == VictimType.USER
    assert classify_email_type("ceo@acme.com") == VictimType.USER
    assert classify_email_type("support@acme.com") == VictimType.USER


# ---------------------------------------------------------------------------
# Monitored-domain gating — the critical correctness boundary
# ---------------------------------------------------------------------------

def test_unmonitored_domain_does_not_create_victim(db: Session) -> None:
    """The single most important invariant: emails on domains we
    don't monitor must NEVER create Victim rows.  Caller is
    responsible for emitting an Indicator instead — verified at the
    integration layer."""
    kit = _make_kit(db)
    # No monitored domains seeded.

    result = observe_victim_email(
        db, kit.id, "attacker@evil.ru",
        VictimObservationSource.OAUTH_STATE,
    )

    assert result is None
    assert db.query(Victim).count() == 0
    assert db.query(KitVictim).count() == 0


def test_monitored_domain_creates_victim(db: Session) -> None:
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    victim = observe_victim_email(
        db, kit.id, "John.Doe@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )

    assert victim is not None
    assert victim.email == "john.doe@acme.com"  # lowercased
    assert victim.domain == "acme.com"
    assert victim.type == VictimType.USER
    # A junction row was created with the source channel.
    obs = db.query(KitVictim).all()
    assert len(obs) == 1
    assert obs[0].kit_id == kit.id
    assert obs[0].victim_id == victim.id
    assert obs[0].source == VictimObservationSource.OAUTH_STATE


def test_suffix_match_covers_subdomains(db: Session) -> None:
    """Subdomains of a monitored domain are also monitored — common
    setup where the parent ``acme.com`` covers ``mail.acme.com`` and
    ``it.acme.com`` without needing a row per subsidiary subdomain."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    victim = observe_victim_email(
        db, kit.id, "alice@mail.acme.com",
        VictimObservationSource.EML_TO,
    )

    assert victim is not None
    assert victim.domain == "mail.acme.com"


def test_suffix_match_does_not_match_lookalikes(db: Session) -> None:
    """``acme.com`` must NOT match ``evil-acme.com`` or ``acme.com.evil.ru``
    — naive substring match would, our suffix logic doesn't."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    assert observe_victim_email(
        db, kit.id, "user@evil-acme.com",
        VictimObservationSource.OAUTH_STATE,
    ) is None
    assert observe_victim_email(
        db, kit.id, "user@acme.com.evil.ru",
        VictimObservationSource.OAUTH_STATE,
    ) is None
    assert db.query(Victim).count() == 0


def test_subsidiary_domains_need_their_own_rows(db: Session) -> None:
    """``acme-hr.com`` doesn't share the parent ``acme.com`` — the
    enterprise has to add it explicitly.  This locks in the
    documented behavior so a future "fuzzy match" change can't
    silently expand the scope."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")  # parent only

    assert observe_victim_email(
        db, kit.id, "alice@acme-hr.com",
        VictimObservationSource.OAUTH_STATE,
    ) is None

    _add_monitored(db, "acme-hr.com")  # operator adds the subsidiary

    victim = observe_victim_email(
        db, kit.id, "alice@acme-hr.com",
        VictimObservationSource.OAUTH_STATE,
    )
    assert victim is not None
    assert victim.domain == "acme-hr.com"


# ---------------------------------------------------------------------------
# Idempotency — the whole pipeline can re-run safely
# ---------------------------------------------------------------------------

def test_repeated_same_source_observation_is_idempotent(db: Session) -> None:
    """Chain steps re-execute on Celery redelivery (per the
    chain_cursor recovery flow).  Re-observing the same triple
    must not produce duplicate rows."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )

    assert db.query(Victim).count() == 1
    assert db.query(KitVictim).count() == 1


def test_same_victim_different_source_creates_distinct_observations(
    db: Session,
) -> None:
    """A single victim can be observed multiple ways within one kit
    (e.g. OAuth state AND AITM URL fragment).  Each source channel
    gets its own row so the per-victim source breakdown is accurate."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.AITM_URL_FRAGMENT,
    )
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.EML_TO,
    )

    assert db.query(Victim).count() == 1
    sources = sorted(
        row[0].value for row in db.query(KitVictim.source).all()
    )
    assert sources == [
        VictimObservationSource.AITM_URL_FRAGMENT.value,
        VictimObservationSource.EML_TO.value,
        VictimObservationSource.OAUTH_STATE.value,
    ]


# ---------------------------------------------------------------------------
# first_seen / last_seen drift
# ---------------------------------------------------------------------------

def test_first_seen_and_last_seen_track_observation_window(
    db: Session,
) -> None:
    """The denormalized timestamps on Victim must accurately bracket
    the observation window across multiple kits over time — that's
    what drives the "first targeted X days ago" UI."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    t_old = datetime(2026, 1, 15, tzinfo=UTC)
    t_mid = datetime(2026, 2, 20, tzinfo=UTC)
    t_new = datetime(2026, 4, 10, tzinfo=UTC)

    # Out-of-order observations — first/last must converge regardless.
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE, observed_at=t_mid,
    )
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.EML_TO, observed_at=t_new,
    )
    observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.AITM_URL_FRAGMENT, observed_at=t_old,
    )

    # SQLite strips tz on round-trip; production Postgres preserves
    # it.  Compare wall-clock components so this works both places.
    victim = db.query(Victim).one()
    assert victim.first_seen.replace(tzinfo=None) == t_old.replace(tzinfo=None)
    assert victim.last_seen.replace(tzinfo=None) == t_new.replace(tzinfo=None)


def test_default_observed_at_uses_now(db: Session) -> None:
    """Caller can omit ``observed_at``; we default to now()."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")
    before = datetime.now(UTC)

    victim = observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )

    after = datetime.now(UTC) + timedelta(seconds=1)
    assert victim is not None
    assert before <= victim.first_seen <= after


# ---------------------------------------------------------------------------
# Robustness — defensive against attacker-controlled inputs
# ---------------------------------------------------------------------------

def test_unparseable_email_is_silent_no_op(db: Session) -> None:
    """observe_victim_email is called with attacker-controlled
    strings (anything that ends up in OAuth ``state``).  Garbage
    input must not crash the surrounding chain step."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    for bad in [None, "", "no-at-sign", "  ", "@nolocal.com",
                "noatleastoneat", "double@@at.com"]:
        result = observe_victim_email(
            db, kit.id, bad,
            VictimObservationSource.OAUTH_STATE,
        )
        assert result is None
    assert db.query(Victim).count() == 0


def test_missing_kit_does_not_crash(db: Session) -> None:
    """Stale callsite (a kit_id that's been deleted) shouldn't take
    out the surrounding task.  Returns None and logs a warning."""
    _add_monitored(db, "acme.com")
    fake_kit_id = uuid.uuid4()

    result = observe_victim_email(
        db, fake_kit_id, "alice@acme.com",
        VictimObservationSource.OAUTH_STATE,
    )

    assert result is None
    assert db.query(Victim).count() == 0


def test_email_normalized_to_lowercase(db: Session) -> None:
    """Mixed-case observations should converge on a single Victim
    row keyed by the canonical lowercased email."""
    kit = _make_kit(db)
    _add_monitored(db, "acme.com")

    v1 = observe_victim_email(
        db, kit.id, "Alice@ACME.com",
        VictimObservationSource.OAUTH_STATE,
    )
    v2 = observe_victim_email(
        db, kit.id, "alice@acme.com",
        VictimObservationSource.EML_TO,
    )

    assert v1 is not None and v2 is not None
    assert v1.id == v2.id
    assert v1.email == "alice@acme.com"
    assert v1.domain == "acme.com"
