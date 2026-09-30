"""add stages, resources, stage_resources for the attack-flow model

Introduces the stage/flow data model: one page the victim's browser
actually landed on becomes a ``stages`` row (with role + fingerprints),
sub-resources are content-addressed in ``resources`` and linked per-load
via ``stage_resources``.  See :mod:`darla.models.stage` and
:mod:`darla.models.resource`.

Revision ID: z6v2w3x4y5q7
Revises: y5u1v2w3x4p6
Create Date: 2026-09-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "z6v2w3x4y5q7"
down_revision: Union[str, None] = "y5u1v2w3x4p6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# SQLAlchemy persists Enum members by NAME (uppercase) — see the
# project's enum-casing note; keep these labels uppercase.
_STAGE_ROLE = sa.Enum(
    "LURE", "REDIRECTOR", "BOT_CHECK", "INTERSTITIAL", "EMAIL_GATE",
    "CRED_CAPTURE", "DECOY", "POST_SUBMIT", "UNKNOWN",
    name="stagerole",
)


def upgrade() -> None:
    # resources — content-addressed sub-resource store.
    op.create_table(
        "resources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("tlsh", sa.String(length=72), nullable=True),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256", name="uq_resources_sha256"),
    )
    op.create_index("ix_resources_tlsh", "resources", ["tlsh"])

    # stages — one per page the victim landed on.
    op.create_table(
        "stages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kit_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("role", _STAGE_ROLE, nullable=False),
        sa.Column("nav_method", sa.String(length=32), nullable=True),
        sa.Column("body_path", sa.Text(), nullable=True),
        sa.Column("screenshot_path", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("tlsh_raw", sa.String(length=72), nullable=True),
        sa.Column("tlsh_rendered", sa.String(length=72), nullable=True),
        sa.Column("skeleton_hash", sa.String(length=64), nullable=True),
        sa.Column("request_shape_hash", sa.String(length=64), nullable=True),
        sa.Column("screenshot_phash", sa.String(length=32), nullable=True),
        sa.Column("aitm_baseline", sa.String(length=64), nullable=True),
        sa.Column("tlsh_bucket", sa.String(length=8), nullable=True),
        sa.Column("fingerprint", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("dwell_seconds", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["kit_id"], ["kits.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_stages_kit_id", "stages", ["kit_id"])
    op.create_index("ix_stages_host", "stages", ["host"])
    op.create_index("ix_stages_role", "stages", ["role"])
    op.create_index("ix_stages_tlsh_raw", "stages", ["tlsh_raw"])
    op.create_index("ix_stages_tlsh_rendered", "stages", ["tlsh_rendered"])
    op.create_index("ix_stages_skeleton_hash", "stages", ["skeleton_hash"])
    op.create_index("ix_stages_request_shape_hash", "stages", ["request_shape_hash"])
    op.create_index("ix_stages_screenshot_phash", "stages", ["screenshot_phash"])
    op.create_index("ix_stages_tlsh_bucket", "stages", ["tlsh_bucket"])
    op.create_index("ix_stages_kit_seq", "stages", ["kit_id", "seq"])
    op.create_index("ix_stages_role_bucket", "stages", ["role", "tlsh_bucket"])

    # stage_resources — junction with per-load context.
    op.create_table(
        "stage_resources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("initiator", sa.String(length=16), nullable=True),
        sa.Column("doc_seq", sa.Integer(), nullable=True),
        sa.Column("ts", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["stage_id"], ["stages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["resource_id"], ["resources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_stage_resources_stage_id", "stage_resources", ["stage_id"])
    op.create_index("ix_stage_resources_resource_id", "stage_resources", ["resource_id"])
    op.create_index(
        "ix_stage_resources_stage_seq", "stage_resources", ["stage_id", "doc_seq"],
    )


def downgrade() -> None:
    op.drop_table("stage_resources")
    op.drop_table("stages")
    op.drop_index("ix_resources_tlsh", table_name="resources")
    op.drop_table("resources")
    _STAGE_ROLE.drop(op.get_bind(), checkfirst=True)
