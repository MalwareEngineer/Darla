"""``darla-admin`` CLI — behavioral tests via Typer's CliRunner.

Each subcommand group is exercised against an in-memory async SQLite
DB.  The CLI's :func:`run_async` wrapper drives the same async session
factory the rest of the app uses; we patch it to point at the test
DB so commands behave identically to production but without touching
Postgres.

Implementation note on event loops: these tests are intentionally
*synchronous* (no ``@pytest.mark.asyncio``).  The Typer CliRunner
invokes commands which internally call ``asyncio.run(...)`` — that
won't work nested inside another running loop, so we keep the test
side sync and use ``asyncio.run`` ourselves for setup/teardown
helpers.  The fixture uses :class:`StaticPool` so SQLite in-memory
survives across multiple ``asyncio.run`` calls (each call would
otherwise get a fresh connection and lose the data).
"""

from __future__ import annotations

import asyncio
import csv
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from typer.testing import CliRunner

from darla.admin.cli import app as darla_admin
from darla.models import (
    AuditLog,
    Base,
    MonitoredDomain,
    User,
    UserRole,
    Victim,
)
from darla.models.victim import VictimType


# ---------------------------------------------------------------------------
# Async SQLite harness, but the TEST is sync — see module docstring.
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_db():
    pytest.importorskip("aiosqlite")

    # StaticPool keeps a single connection alive across ``asyncio.run``
    # calls so the in-memory DB doesn't reset between operations.
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async def _create():
        async with engine.begin() as conn:
            await conn.run_sync(
                Base.metadata.create_all,
                tables=[
                    User.__table__,
                    AuditLog.__table__,
                    MonitoredDomain.__table__,
                    Victim.__table__,
                ],
            )

    asyncio.run(_create())
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Patch the helpers module so every CLI invocation under test uses
    # this DB instead of the real one.
    with patch("darla.admin._helpers.async_session_factory", factory):
        yield factory

    asyncio.run(engine.dispose())


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# Sync wrappers that bury the asyncio.run boilerplate.  Each one
# opens its own session, does the work, commits, closes.  Keeps the
# tests readable.


def _query_audit_rows(factory) -> list[AuditLog]:
    async def _go():
        async with factory() as s:
            return list((await s.scalars(select(AuditLog))).all())
    return asyncio.run(_go())


def _seed_user(
    factory,
    *,
    subject: str = "subject-1",
    upn: str = "alice@example.com",
    role: UserRole = UserRole.ANALYST,
    role_override: UserRole | None = None,
    disabled: bool = False,
) -> None:
    async def _go():
        async with factory() as s:
            s.add(User(
                id=uuid.uuid4(),
                oidc_subject=subject,
                upn=upn,
                display_name=upn.split("@")[0].title(),
                role=role,
                role_override=role_override,
                last_login_at=datetime.now(UTC),
                disabled_at=datetime.now(UTC) if disabled else None,
            ))
            await s.commit()
    asyncio.run(_go())


def _get_user(factory, subject: str) -> User | None:
    async def _go():
        async with factory() as s:
            return await s.scalar(select(User).where(User.oidc_subject == subject))
    return asyncio.run(_go())


def _all_monitored(factory) -> list[MonitoredDomain]:
    async def _go():
        async with factory() as s:
            return list((await s.scalars(select(MonitoredDomain))).all())
    return asyncio.run(_go())


def _seed_monitored(factory, domains: list[str]) -> None:
    async def _go():
        async with factory() as s:
            for d in domains:
                s.add(MonitoredDomain(domain=d))
            await s.commit()
    asyncio.run(_go())


def _seed_victim(
    factory,
    *,
    email: str,
    display_name: str | None,
    type_: VictimType,
    notes: str | None,
) -> None:
    async def _go():
        async with factory() as s:
            s.add(Victim(
                id=uuid.uuid4(),
                email=email,
                domain=email.split("@", 1)[1],
                display_name=display_name,
                type=type_,
                notes=notes,
            ))
            await s.commit()
    asyncio.run(_go())


def _get_victim(factory, email: str) -> Victim | None:
    async def _go():
        async with factory() as s:
            return await s.scalar(select(Victim).where(Victim.email == email))
    return asyncio.run(_go())


def _seed_audit(factory, rows: list[dict]) -> None:
    async def _go():
        async with factory() as s:
            for r in rows:
                s.add(AuditLog(
                    id=uuid.uuid4(),
                    actor_subject=r.get("actor_subject"),
                    actor_upn=r.get("actor_upn"),
                    auth_mode=r.get("auth_mode", "oidc"),
                    method=r.get("method", "GET"),
                    path=r["path"],
                    status_code=r.get("status_code", 200),
                    response_ms=r.get("response_ms", 1),
                    request_id=r.get("request_id", str(uuid.uuid4())),
                ))
            await s.commit()
    asyncio.run(_go())


# ---------------------------------------------------------------------------
# user list
# ---------------------------------------------------------------------------


class TestUserList:
    def test_list_users_audited(self, admin_db, runner: CliRunner) -> None:
        _seed_user(admin_db, subject="s1", upn="a@x.com")
        _seed_user(admin_db, subject="s2", upn="b@x.com", role=UserRole.VIEWER)

        result = runner.invoke(darla_admin, ["user", "list"])

        assert result.exit_code == 0
        assert "a@x.com" in result.stdout
        assert "b@x.com" in result.stdout
        audits = _query_audit_rows(admin_db)
        assert any(r.path == "user.list" for r in audits)

    def test_list_users_role_filter(self, admin_db, runner: CliRunner) -> None:
        # UPNs are intentionally short so Rich's table doesn't truncate
        # with an ellipsis (which would defeat substring matching).
        _seed_user(admin_db, subject="s1", upn="a@x", role=UserRole.ANALYST)
        _seed_user(admin_db, subject="s2", upn="v@x", role=UserRole.VIEWER)

        result = runner.invoke(darla_admin, ["user", "list", "--role", "viewer"])

        assert result.exit_code == 0
        # Match on the unique subject (always rendered in full because
        # the column allows folding) rather than the easily-truncated UPN.
        assert "s2" in result.stdout
        assert "s1" not in result.stdout

    def test_list_users_bad_role_rejects(self, admin_db, runner: CliRunner) -> None:
        # Bad input → exit 2, no DB queries.
        result = runner.invoke(darla_admin, ["user", "list", "--role", "admin"])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# user disable / enable
# ---------------------------------------------------------------------------


class TestUserDisableEnable:
    def test_disable_sets_timestamp(self, admin_db, runner: CliRunner) -> None:
        _seed_user(admin_db, subject="kill-me", upn="z@x.com")

        result = runner.invoke(darla_admin, ["user", "disable", "kill-me"])

        assert result.exit_code == 0
        u = _get_user(admin_db, "kill-me")
        assert u is not None
        assert u.disabled_at is not None

    def test_enable_clears_timestamp(self, admin_db, runner: CliRunner) -> None:
        _seed_user(admin_db, subject="resurrect", upn="z@x.com", disabled=True)

        result = runner.invoke(darla_admin, ["user", "enable", "resurrect"])

        assert result.exit_code == 0
        u = _get_user(admin_db, "resurrect")
        assert u.disabled_at is None

    def test_disable_unknown_user_exits_1(self, admin_db, runner: CliRunner) -> None:
        # Expected-failure code path — not the same as bad input (exit 2).
        result = runner.invoke(darla_admin, ["user", "disable", "no-such-user"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# user set-role-override / clear-role-override
# ---------------------------------------------------------------------------


class TestRoleOverride:
    def test_set_override_persists(self, admin_db, runner: CliRunner) -> None:
        _seed_user(admin_db, subject="ovr", upn="o@x.com", role=UserRole.ANALYST)

        result = runner.invoke(
            darla_admin, ["user", "set-role-override", "ovr", "viewer"],
        )

        assert result.exit_code == 0
        u = _get_user(admin_db, "ovr")
        # Override takes effect — effective_role flips even though
        # IdP-derived ``role`` is unchanged.  This is the whole point
        # of having a separate override column (RFC §3 decision #5).
        assert u.role_override is UserRole.VIEWER
        assert u.role is UserRole.ANALYST
        assert u.effective_role is UserRole.VIEWER

    def test_clear_override(self, admin_db, runner: CliRunner) -> None:
        _seed_user(
            admin_db,
            subject="ovr",
            upn="o@x.com",
            role=UserRole.ANALYST,
            role_override=UserRole.VIEWER,
        )

        result = runner.invoke(darla_admin, ["user", "clear-role-override", "ovr"])

        assert result.exit_code == 0
        u = _get_user(admin_db, "ovr")
        assert u.role_override is None


# ---------------------------------------------------------------------------
# monitored-domain reload
# ---------------------------------------------------------------------------


class TestMonitoredDomainReload:
    def _write_yaml(self, tmp_path: Path, entries: list[dict]) -> Path:
        path = tmp_path / "monitored_domains.yaml"
        path.write_text(yaml.safe_dump({"domains": entries}), encoding="utf-8")
        return path

    def test_reload_inserts_new_domains(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        yaml_path = self._write_yaml(tmp_path, [
            {"domain": "acme.com", "description": "primary"},
            {"domain": "subsidiary.acme", "description": None},
        ])

        result = runner.invoke(
            darla_admin,
            ["monitored-domain", "reload", "--source", str(yaml_path)],
        )

        assert result.exit_code == 0
        rows = _all_monitored(admin_db)
        assert {r.domain for r in rows} == {"acme.com", "subsidiary.acme"}

    def test_reload_deletes_missing_domains(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        # Seed three; YAML only mentions two → third deleted.
        _seed_monitored(admin_db, ["a.com", "b.com", "c.com"])
        yaml_path = self._write_yaml(tmp_path, [
            {"domain": "a.com"},
            {"domain": "b.com"},
        ])

        result = runner.invoke(
            darla_admin,
            ["monitored-domain", "reload", "--source", str(yaml_path)],
        )

        assert result.exit_code == 0
        rows = _all_monitored(admin_db)
        assert {r.domain for r in rows} == {"a.com", "b.com"}

    def test_reload_dry_run_makes_no_changes(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        yaml_path = self._write_yaml(tmp_path, [
            {"domain": "would-be-added.com"},
        ])

        result = runner.invoke(
            darla_admin,
            ["monitored-domain", "reload", "--source", str(yaml_path), "--dry-run"],
        )

        assert result.exit_code == 0
        # Nothing committed — dry-run must be observably read-only.
        rows = _all_monitored(admin_db)
        assert not any(r.domain == "would-be-added.com" for r in rows)

    def test_reload_idempotent(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        yaml_path = self._write_yaml(tmp_path, [
            {"domain": "stable.com", "description": "no change"},
        ])

        runner.invoke(darla_admin, ["monitored-domain", "reload", "--source", str(yaml_path)])
        result = runner.invoke(
            darla_admin, ["monitored-domain", "reload", "--source", str(yaml_path)],
        )

        assert result.exit_code == 0
        assert "nothing to do" in result.stdout.lower()

    def test_reload_rejects_missing_file(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        result = runner.invoke(
            darla_admin,
            ["monitored-domain", "reload", "--source", str(tmp_path / "missing.yaml")],
        )
        assert result.exit_code == 2

    def test_reload_rejects_malformed_yaml(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("domains:\n  - missing_domain_key: true\n", encoding="utf-8")
        result = runner.invoke(
            darla_admin, ["monitored-domain", "reload", "--source", str(bad)],
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# victim reload
# ---------------------------------------------------------------------------


class TestVictimReload:
    def _write_csv(self, tmp_path: Path, rows: list[dict]) -> Path:
        path = tmp_path / "victims.csv"
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["email", "display_name", "type", "notes"],
            )
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        return path

    def test_csv_creates_new_victims(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        csv_path = self._write_csv(tmp_path, [
            {"email": "alice@acme.com", "display_name": "Alice", "type": "user", "notes": ""},
            {"email": "bob@acme.com", "display_name": "Bob", "type": "exec", "notes": "VP"},
        ])

        result = runner.invoke(
            darla_admin, ["victim", "reload", "--source", str(csv_path)],
        )

        assert result.exit_code == 0
        alice = _get_victim(admin_db, "alice@acme.com")
        bob = _get_victim(admin_db, "bob@acme.com")
        assert alice is not None
        assert alice.display_name == "Alice"
        assert bob.type is VictimType.EXEC

    def test_csv_does_not_blank_existing_fields(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        # Re-importing a CSV with empty ``notes`` must NOT blank notes
        # already populated by other paths.
        _seed_victim(
            admin_db,
            email="alice@acme.com",
            display_name="Alice",
            type_=VictimType.USER,
            notes="manually-added context",
        )

        csv_path = self._write_csv(tmp_path, [
            {"email": "alice@acme.com", "display_name": "Alice Updated", "type": "", "notes": ""},
        ])

        result = runner.invoke(
            darla_admin, ["victim", "reload", "--source", str(csv_path)],
        )

        assert result.exit_code == 0
        v = _get_victim(admin_db, "alice@acme.com")
        assert v.display_name == "Alice Updated"  # display_name DID change
        assert v.notes == "manually-added context"  # notes did NOT get blanked

    def test_csv_rejects_bad_type(
        self, admin_db, runner: CliRunner, tmp_path: Path,
    ) -> None:
        csv_path = self._write_csv(tmp_path, [
            {"email": "alice@acme.com", "display_name": "Alice", "type": "wizard", "notes": ""},
        ])

        result = runner.invoke(
            darla_admin, ["victim", "reload", "--source", str(csv_path)],
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# audit recent
# ---------------------------------------------------------------------------


class TestAuditRecent:
    def test_renders_recent_rows(self, admin_db, runner: CliRunner) -> None:
        _seed_audit(admin_db, [
            {"actor_subject": f"sub-{i}", "path": f"/api/v1/kits/{i}"}
            for i in range(3)
        ])

        result = runner.invoke(darla_admin, ["audit", "recent", "--since", "24h"])

        assert result.exit_code == 0
        for i in range(3):
            assert f"sub-{i}" in result.stdout

    def test_filter_by_user(self, admin_db, runner: CliRunner) -> None:
        _seed_audit(admin_db, [
            {"actor_subject": "alice", "path": "/api/v1/kits"},
            {"actor_subject": "bob", "path": "/api/v1/kits"},
        ])

        result = runner.invoke(
            darla_admin,
            ["audit", "recent", "--user", "alice", "--since", "24h"],
        )

        assert result.exit_code == 0
        assert "alice" in result.stdout
        assert "bob" not in result.stdout

    def test_filter_by_path_prefix(self, admin_db, runner: CliRunner) -> None:
        _seed_audit(admin_db, [
            {"actor_subject": "x", "path": "/api/v1/victims/abc"},
            {"actor_subject": "x", "path": "/api/v1/kits"},
        ])

        result = runner.invoke(
            darla_admin,
            ["audit", "recent", "--path", "/api/v1/victims", "--since", "24h"],
        )

        assert result.exit_code == 0
        assert "victims" in result.stdout
        assert "/api/v1/kits" not in result.stdout

    def test_invalid_since_format_rejects(
        self, admin_db, runner: CliRunner,
    ) -> None:
        result = runner.invoke(
            darla_admin, ["audit", "recent", "--since", "forever"],
        )
        # BadParameter from Typer → exit 2.
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Audit trail — every CLI invocation must leave a row.
# ---------------------------------------------------------------------------


class TestCliAuditing:
    def test_successful_command_writes_audit_row(
        self, admin_db, runner: CliRunner,
    ) -> None:
        _seed_user(admin_db, subject="t1", upn="t1@x.com")
        result = runner.invoke(darla_admin, ["user", "disable", "t1"])

        assert result.exit_code == 0
        rows = _query_audit_rows(admin_db)
        disable_rows = [r for r in rows if r.path == "user.disable"]
        assert len(disable_rows) == 1
        assert disable_rows[0].actor_subject is not None
        assert disable_rows[0].actor_subject.startswith("cli:")
        assert disable_rows[0].method == "CLI"
        assert disable_rows[0].auth_mode == "cli"
        assert disable_rows[0].status_code == 0

    def test_expected_failure_audited_with_status_1(
        self, admin_db, runner: CliRunner,
    ) -> None:
        # User not found = expected failure.  Audit row still written,
        # status=1 so audit reviewers can filter to "things that didn't
        # do anything because the target was missing".
        result = runner.invoke(darla_admin, ["user", "disable", "ghost"])

        assert result.exit_code == 1
        rows = _query_audit_rows(admin_db)
        disable_rows = [r for r in rows if r.path == "user.disable"]
        assert len(disable_rows) == 1
        assert disable_rows[0].status_code == 1
