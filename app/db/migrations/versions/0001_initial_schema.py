"""Initial schema.

Revision ID: 0001
Revises:
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# VARCHAR + CHECK rather than native PostgreSQL enums, so adding a value later is an
# ordinary constraint change instead of an ALTER TYPE dance.
JOB_STATUS = sa.Enum(
    "pending", "running", "done", "failed", name="job_status", native_enum=False, length=16
)
RUN_STATUS = sa.Enum(
    "success", "failed", "skipped", name="run_status", native_enum=False, length=16
)
SEVERITY = sa.Enum(
    "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity", native_enum=False, length=16
)

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "image",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tag", sa.String(128), nullable=False),
        sa.Column("scan_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        # Plain BigInteger, not an FK: image and scan_run would otherwise reference
        # each other, and the pointer is maintained in the same transaction anyway.
        sa.Column("current_scan_run_id", sa.BigInteger(), nullable=True),
        sa.Column("last_scan_at", TS, nullable=True),
        sa.Column("last_scan_status", RUN_STATUS, nullable=True),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", "tag", name="uq_image_name_tag"),
        sa.CheckConstraint(
            "scan_interval_seconds IS NULL OR scan_interval_seconds > 0",
            name="ck_image_interval_positive",
        ),
    )

    op.create_table(
        "scan_run",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "image_id",
            sa.Integer(),
            sa.ForeignKey("image.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scan_job_id", sa.BigInteger(), nullable=True),
        sa.Column("started_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", TS, nullable=True),
        sa.Column("status", RUN_STATUS, nullable=False),
        sa.Column("digest", sa.String(128), nullable=True),
        sa.Column("trivy_version", sa.String(64), nullable=True),
        sa.Column("trivy_db_version", sa.String(64), nullable=True),
        sa.Column("scan_flags_hash", sa.String(64), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.execute(
        "CREATE INDEX ix_scan_run_image_completed "
        "ON scan_run (image_id, completed_at DESC)"
    )

    op.create_table(
        "scan_job",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "image_id",
            sa.Integer(),
            sa.ForeignKey("image.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", JOB_STATUS, server_default="pending", nullable=False),
        sa.Column("priority", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("scheduled_for", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("lease_until", TS, nullable=True),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
    )
    op.execute(
        "CREATE INDEX ix_scan_job_claimable ON scan_job (priority DESC, scheduled_for) "
        "WHERE status = 'pending'"
    )
    # The structural guarantee that one image cannot be queued twice.
    op.execute(
        "CREATE UNIQUE INDEX uq_scan_job_active ON scan_job (image_id) "
        "WHERE status IN ('pending', 'running')"
    )
    op.execute(
        "CREATE INDEX ix_scan_job_lease ON scan_job (lease_until) WHERE status = 'running'"
    )

    op.create_table(
        "package",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("type", sa.String(64), server_default="unknown", nullable=False),
        sa.UniqueConstraint("name", "version", "type", name="uq_package_nvt"),
    )

    op.create_table(
        "cve",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("max_severity", SEVERITY, server_default="UNKNOWN", nullable=False),
        sa.Column(
            "max_severity_rank", sa.SmallInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("published_at", TS, nullable=True),
        sa.Column("last_modified_at", TS, nullable=True),
    )
    op.create_index("ix_cve_max_severity_rank", "cve", ["max_severity_rank"])

    op.create_table(
        "finding",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "image_id",
            sa.Integer(),
            sa.ForeignKey("image.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cve_id",
            sa.String(64),
            sa.ForeignKey("cve.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "package_id",
            sa.BigInteger(),
            sa.ForeignKey("package.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("fixed_version", sa.String(255), nullable=True),
        sa.Column("severity", SEVERITY, nullable=False),
        sa.Column("severity_rank", sa.SmallInteger(), nullable=False),
        sa.Column("first_seen_run_id", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_run_id", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("image_id", "cve_id", "package_id", name="uq_finding_img_cve_pkg"),
    )
    op.create_index("ix_finding_cve", "finding", ["cve_id"])
    op.create_index("ix_finding_image_severity", "finding", ["image_id", "severity_rank"])
    op.create_index("ix_finding_last_seen", "finding", ["last_seen_run_id"])


def downgrade() -> None:
    op.drop_table("finding")
    op.drop_index("ix_cve_max_severity_rank", table_name="cve")
    op.drop_table("cve")
    op.drop_table("package")
    op.drop_table("scan_job")
    op.drop_table("scan_run")
    op.drop_table("image")
