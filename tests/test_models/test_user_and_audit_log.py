"""Phase 1 schema models — User, AuditLog, attribution-evidence subject column.

Two layers:

1. Pure-Python tests for behaviour that doesn't require a database
   (UserRole enum values, ``User.effective_role`` override semantics,
   ``__repr__`` shapes, ``AUTH_MODE_*`` constants).
2. In-memory SQLite tests for the storage shape — inserts, the
   ``oidc_subject`` uniqueness constraint, nullable ``actor_subject``
   on AuditLog, and JSONB ``extra`` round-tripping (SQLAlchemy
   downgrades JSONB to JSON-equivalent on SQLite, which is sufficient
   for shape verification — Postgres-specific operator behaviour is
   exercised at the integration layer).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from darla.models import (
    AUTH_MODE_DISABLED,
    AUTH_MODE_OIDC,
    AuditLog,
    Base,
    User,
    UserRole,
)

# ---------------------------------------------------------------------------
# Pure-Python (no DB) — behaviour that lives entirely on the model class.
# ---------------------------------------------------------------------------


class TestUserRoleEnum:
    def test_only_two_roles_exist(self) -> None:
        # Two roles is intentional — RFC 0001 §3 decision #2.  Adding a
        # third without RFC update is a design regression.
        assert {r.value for r in UserRole} == {"viewer", "analyst"}

    def test_string_values_lowercase(self) -> None:
        # Lowercase string values match the OIDC role-claim convention
        # used in PK_OIDC_VIEWER_ROLE_VALUE / PK_OIDC_ANALYST_ROLE_VALUE
        # comparisons after .lower() normalisation.
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.ANALYST.value == "analyst"


class TestUserEffectiveRole:
    """The ``effective_role`` property is the only authorization-safe
    way to read a user's role — direct ``user.role`` access bypasses the
    CLI-set override and is a security bug.  These tests pin the
    contract."""

    def _user(self, role: UserRole, override: UserRole | None = None) -> User:
        return User(
            id=uuid.uuid4(),
            oidc_subject="subject-test",
            upn="test@example.com",
            display_name="Test User",
            role=role,
            role_override=override,
            last_login_at=datetime.now(UTC),
        )

    def test_no_override_returns_role(self) -> None:
        u = self._user(UserRole.ANALYST, override=None)
        assert u.effective_role is UserRole.ANALYST

    def test_override_wins_when_set(self) -> None:
        # The whole point of role_override is to instantly downgrade
        # someone whose IdP group removal hasn't propagated yet.
        u = self._user(UserRole.ANALYST, override=UserRole.VIEWER)
        assert u.effective_role is UserRole.VIEWER

    def test_override_can_promote(self) -> None:
        # Symmetric — override also wins when promoting (e.g. a viewer
        # tagged for incident-response analyst access without waiting
        # for IdP group sync).
        u = self._user(UserRole.VIEWER, override=UserRole.ANALYST)
        assert u.effective_role is UserRole.ANALYST


class TestUserRepr:
    def test_repr_contains_upn_and_role(self) -> None:
        u = User(
            id=uuid.uuid4(),
            oidc_subject="abc",
            upn="alice@example.com",
            display_name="Alice",
            role=UserRole.ANALYST,
            last_login_at=datetime.now(UTC),
        )
        r = repr(u)
        assert "alice@example.com" in r
        assert "analyst" in r
        assert "disabled" not in r

    def test_repr_marks_disabled(self) -> None:
        u = User(
            id=uuid.uuid4(),
            oidc_subject="abc",
            upn="alice@example.com",
            display_name="Alice",
            role=UserRole.ANALYST,
            last_login_at=datetime.now(UTC),
            disabled_at=datetime.now(UTC),
        )
        assert "disabled" in repr(u)

    def test_repr_uses_effective_role(self) -> None:
        # repr should show what authorization decisions actually use,
        # not the token-derived role.  Otherwise an analyst whose
        # access has been emergency-overridden to viewer would still
        # render as "analyst" in admin tooling — confusing.
        u = User(
            id=uuid.uuid4(),
            oidc_subject="abc",
            upn="alice@example.com",
            display_name="Alice",
            role=UserRole.ANALYST,
            role_override=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        )
        assert "viewer" in repr(u)


class TestAuthModeConstants:
    def test_constants_are_stable_strings(self) -> None:
        # These strings are persisted to audit_log.auth_mode forever —
        # changing them retroactively breaks every existing audit query.
        # Pin the values explicitly.
        assert AUTH_MODE_OIDC == "oidc"
        assert AUTH_MODE_DISABLED == "disabled"


class TestAuditLogRepr:
    def _row(self, actor: str | None) -> AuditLog:
        return AuditLog(
            id=uuid.uuid4(),
            timestamp=datetime(2026, 5, 11, 12, 0, 0, tzinfo=UTC),
            actor_subject=actor,
            actor_upn=None,
            auth_mode=AUTH_MODE_OIDC if actor else AUTH_MODE_DISABLED,
            method="GET",
            path="/api/v1/kits",
            status_code=200,
            response_ms=42,
            request_id="req-1",
        )

    def test_repr_with_actor(self) -> None:
        r = repr(self._row("subject-abc"))
        assert "subject-abc" in r
        assert "GET" in r
        assert "/api/v1/kits" in r
        assert "200" in r

    def test_repr_anonymous(self) -> None:
        # Disabled-mode rows have actor_subject=None — repr should
        # render them as "anon" so audit-log dumps stay readable.
        r = repr(self._row(None))
        assert "anon" in r


# ---------------------------------------------------------------------------
# In-memory SQLite — storage-shape verification.
#
# The schema uses Postgres-specific UUID + JSONB types but SQLAlchemy
# downgrades both to portable equivalents on SQLite create_all.  That's
# enough to verify columns exist, types are sensible, NOT NULL is
# enforced, the unique constraint on oidc_subject works, and JSONB
# round-trips a dict.  Postgres-specific behaviour (JSONB operators,
# index types) is exercised at the integration layer.
# ---------------------------------------------------------------------------


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[
        User.__table__,
        AuditLog.__table__,
    ])
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


class TestUserStorage:
    def test_insert_and_query(self, db: Session) -> None:
        u = User(
            id=uuid.uuid4(),
            oidc_subject="00000000-0000-0000-0000-000000000001",
            upn="alice@example.com",
            display_name="Alice",
            role=UserRole.ANALYST,
            last_login_at=datetime.now(UTC),
        )
        db.add(u)
        db.commit()

        got = db.query(User).filter_by(oidc_subject="00000000-0000-0000-0000-000000000001").one()
        assert got.upn == "alice@example.com"
        assert got.role is UserRole.ANALYST
        assert got.role_override is None
        assert got.disabled_at is None
        assert got.created_at is not None  # server-default fired
        assert got.effective_role is UserRole.ANALYST

    def test_oidc_subject_unique(self, db: Session) -> None:
        # Two users with the same oidc_subject is the JIT race we MUST
        # protect against — if the constraint is dropped, concurrent
        # first-logins would create duplicate rows and split the user's
        # audit trail across them.
        common_subject = "shared-subject"
        db.add(User(
            id=uuid.uuid4(),
            oidc_subject=common_subject,
            upn="a@example.com",
            display_name="A",
            role=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        ))
        db.commit()

        db.add(User(
            id=uuid.uuid4(),
            oidc_subject=common_subject,
            upn="b@example.com",
            display_name="B",
            role=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        ))
        with pytest.raises(IntegrityError):
            db.commit()

    def test_role_override_persists(self, db: Session) -> None:
        u = User(
            id=uuid.uuid4(),
            oidc_subject="override-test",
            upn="x@example.com",
            display_name="X",
            role=UserRole.ANALYST,
            role_override=UserRole.VIEWER,
            last_login_at=datetime.now(UTC),
        )
        db.add(u)
        db.commit()
        db.refresh(u)
        assert u.effective_role is UserRole.VIEWER


class TestAuditLogStorage:
    def _base_row(self, **overrides) -> AuditLog:
        defaults = dict(
            id=uuid.uuid4(),
            actor_subject="subject-x",
            actor_upn="x@example.com",
            auth_mode=AUTH_MODE_OIDC,
            method="GET",
            path="/api/v1/kits",
            status_code=200,
            response_ms=15,
            request_id="req-test-1",
        )
        defaults.update(overrides)
        return AuditLog(**defaults)

    def test_insert_authenticated(self, db: Session) -> None:
        db.add(self._base_row())
        db.commit()
        got = db.query(AuditLog).one()
        assert got.actor_subject == "subject-x"
        assert got.auth_mode == AUTH_MODE_OIDC
        assert got.timestamp is not None  # server-default fired

    def test_insert_disabled_mode_anonymous(self, db: Session) -> None:
        # Disabled-mode (community / local-eval) requests still write
        # audit rows, with actor_subject NULL — see RFC 0001 §16.1.
        db.add(self._base_row(
            actor_subject=None,
            actor_upn=None,
            auth_mode=AUTH_MODE_DISABLED,
        ))
        db.commit()
        got = db.query(AuditLog).one()
        assert got.actor_subject is None
        assert got.auth_mode == AUTH_MODE_DISABLED

    def test_extra_jsonb_roundtrip(self, db: Session) -> None:
        # Sensitive-route reads stash returned IDs in `extra` for
        # "who saw what" reports — verify the dict round-trips.
        victim_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        db.add(self._base_row(
            path="/api/v1/victims",
            extra={"victim_ids": victim_ids, "filter": "domain:acme.com"},
        ))
        db.commit()
        got = db.query(AuditLog).one()
        assert got.extra == {"victim_ids": victim_ids, "filter": "domain:acme.com"}

    @pytest.mark.parametrize("required_field", [
        "auth_mode", "method", "path", "status_code", "response_ms", "request_id",
    ])
    def test_required_fields_enforced(self, db: Session, required_field: str) -> None:
        # Audit rows must carry enough context to be useful in incident
        # response — a row missing method or path is worse than no row.
        kwargs = dict(
            id=uuid.uuid4(),
            actor_subject="subject-x",
            actor_upn="x@example.com",
            auth_mode=AUTH_MODE_OIDC,
            method="GET",
            path="/api/v1/kits",
            status_code=200,
            response_ms=15,
            request_id="req-test-1",
        )
        kwargs.pop(required_field)
        db.add(AuditLog(**kwargs))
        with pytest.raises(IntegrityError):
            db.commit()

    def test_actor_timestamp_query(self, db: Session) -> None:
        # The composite (actor_subject, timestamp) index drives the most
        # common audit query.  Verify the underlying query shape works
        # — the index existence itself is verified at the DDL layer.
        now = datetime.now(UTC)
        db.add_all([
            self._base_row(
                id=uuid.uuid4(), actor_subject="alice",
                request_id=f"r-{i}",
                # Sub-millisecond offset so rows have distinct timestamps
                # in SQLite's TEXT-stored datetime ordering.
            ) for i in range(3)
        ])
        db.add(self._base_row(
            id=uuid.uuid4(), actor_subject="bob", request_id="r-bob",
        ))
        db.commit()

        alice_rows = db.query(AuditLog).filter(
            AuditLog.actor_subject == "alice",
            AuditLog.timestamp >= now - timedelta(minutes=1),
        ).all()
        assert len(alice_rows) == 3
        assert all(r.actor_subject == "alice" for r in alice_rows)
