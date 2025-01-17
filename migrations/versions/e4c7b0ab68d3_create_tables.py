"""Create tables

Revision ID: e4c7b0ab68d3
Revises:
Create Date: 2022-06-03 16:00:02.745086

This migration was auto-generated by Alembic based on these versions of
the model:
- https://github.com/uc-cdis/userdatamodel/blob/2.4.0/userdatamodel/user.py
- https://github.com/uc-cdis/fence/blob/2022.07/fence/models.py
"""
from alembic import context, op
import logging
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from userdatamodel.driver import SQLAlchemyDriver

from bin.old_migration_script import migrate

# revision identifiers, used by Alembic.
revision = "e4c7b0ab68d3"
down_revision = None
branch_labels = None
depends_on = None

logger = logging.getLogger("fence.alembic")


def upgrade():
    # If this is a new instance of Fence, we can run this initial Alembic
    # migration to create the tables. If not, the DB might have been partially
    # migrated by the old migration script and we need to make sure all the
    # old migrations are run, then Alembic can pick up from there and run more
    # recent migrations.
    # The state of the DB after the old migration script runs is the same as
    # after this initial Alembic migration.
    conn = op.get_bind()
    inspector = sa.engine.reflection.Inspector.from_engine(conn)
    tables = inspector.get_table_names()
    if len(tables) > 0 and tables != ["alembic_version"]:
        logger.info(
            "Found existing tables: this is not a new instance of Fence. Running the old migration script... Note that future migrations will be run using Alembic."
        )
        driver = SQLAlchemyDriver(context.config.get_main_option("sqlalchemy.url"))
        migrate(driver)
        return
    else:
        logger.info("No existing tables: running initial migration")

    op.create_table(
        "Group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "assume_role_cache",
        sa.Column("arn", sa.String(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=True),
        sa.Column("aws_access_key_id", sa.String(), nullable=True),
        sa.Column("aws_secret_access_key", sa.String(), nullable=True),
        sa.Column("aws_session_token", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("arn"),
    )
    op.create_table(
        "authorization_provider",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "blacklisted_token",
        sa.Column("jti", sa.String(length=36), nullable=False),
        sa.Column("exp", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_table(
        "cert_audit_logs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("operation", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column(
            "old_values",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.Column(
            "new_values",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "cloud_provider",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("endpoint", sa.String(), nullable=True),
        sa.Column("backend", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("service", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "event_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("target_type", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ga4gh_passport_cache",
        sa.Column("passport_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("user_ids", postgresql.ARRAY(sa.String(length=255)), nullable=False),
        sa.PrimaryKeyConstraint("passport_hash"),
    )
    op.create_table(
        "gcp_assume_role_cache",
        sa.Column("gcp_proxy_group_id", sa.String(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=True),
        sa.Column("gcp_private_key", sa.String(), nullable=True),
        sa.Column("gcp_key_db_entry", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("gcp_proxy_group_id"),
    )
    op.create_table(
        "google_proxy_group",
        sa.Column("id", sa.String(length=90), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "identity_provider",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "organization",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "project",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("auth_id", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("authz", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["project.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("auth_id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "user_audit_logs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("operation", sa.String(), nullable=False),
        sa.Column(
            "old_values",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.Column(
            "new_values",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_refresh_token",
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("userid", sa.Integer(), nullable=True),
        sa.Column("expires", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_table(
        "user_service_account",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("google_unique_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("google_project_id", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "bucket",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["cloud_provider.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "department",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organization.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "service_account_access_privilege",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("service_account_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["service_account_id"], ["user_service_account.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "User",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("id_from_idp", sa.String(), nullable=True),
        sa.Column("display_name", sa.String(), nullable=True),
        sa.Column("phone_number", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=True),
        sa.Column(
            "_last_auth", sa.DateTime(), server_default=sa.text("now()"), nullable=True
        ),
        sa.Column("idp_id", sa.Integer(), nullable=True),
        sa.Column("google_proxy_group_id", sa.String(), nullable=True),
        sa.Column("department_id", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=True),
        sa.Column(
            "additional_info",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["department_id"],
            ["department.id"],
        ),
        sa.ForeignKeyConstraint(
            ["google_proxy_group_id"], ["google_proxy_group.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["idp_id"],
            ["identity_provider.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "google_bucket_access_group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("bucket_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("privileges", postgresql.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(["bucket_id"], ["bucket.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "project_to_bucket",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("bucket_id", sa.Integer(), nullable=True),
        sa.Column("privilege", postgresql.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(["bucket_id"], ["bucket.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "access_privilege",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("privilege", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "user_id is NULL or group_id is NULL", name="check_access_subject"
        ),
        sa.ForeignKeyConstraint(["group_id"], ["Group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["authorization_provider.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "group_id", "project_id", name="uniq_ap"),
    )
    op.create_index(
        "unique_group_project_id",
        "access_privilege",
        ["group_id", "project_id"],
        unique=True,
        postgresql_where=sa.text("user_id is NULL"),
    )
    op.create_index(
        "unique_user_group_id",
        "access_privilege",
        ["user_id", "group_id"],
        unique=True,
        postgresql_where=sa.text("project_id is NULL"),
    )
    op.create_index(
        "unique_user_project_id",
        "access_privilege",
        ["user_id", "project_id"],
        unique=True,
        postgresql_where=sa.text("group_id is NULL"),
    )
    op.create_table(
        "application",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("resources_granted", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("message", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["User.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "authorization_code",
        sa.Column("code", sa.String(length=120), nullable=False),
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("redirect_uri", sa.Text(), nullable=True),
        sa.Column("response_type", sa.Text(), nullable=True),
        sa.Column("auth_time", sa.Integer(), nullable=False),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("nonce", sa.String(), nullable=True),
        sa.Column("refresh_token_expires_in", sa.Integer(), nullable=True),
        sa.Column("_scope", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.create_table(
        "client",
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=True),
        sa.Column("token_endpoint_auth_method", sa.String(length=48), nullable=True),
        sa.Column("grant_type", sa.Text(), nullable=False),
        sa.Column("response_type", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("client_name", sa.String(length=100), nullable=True),
        sa.Column("client_uri", sa.Text(), nullable=True),
        sa.Column("logo_uri", sa.Text(), nullable=True),
        sa.Column("contact", sa.Text(), nullable=True),
        sa.Column("tos_uri", sa.Text(), nullable=True),
        sa.Column("policy_uri", sa.Text(), nullable=True),
        sa.Column("jwks_uri", sa.Text(), nullable=True),
        sa.Column("jwks_text", sa.Text(), nullable=True),
        sa.Column("i18n_metadata", sa.Text(), nullable=True),
        sa.Column("software_id", sa.String(length=36), nullable=True),
        sa.Column("software_version", sa.String(length=48), nullable=True),
        sa.Column("client_id", sa.String(length=40), nullable=False),
        sa.Column("client_secret", sa.String(length=60), nullable=True),
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.Column("description", sa.String(length=400), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("auto_approve", sa.Boolean(), nullable=True),
        sa.Column("is_confidential", sa.Boolean(), nullable=True),
        sa.Column("_redirect_uris", sa.Text(), nullable=True),
        sa.Column("_allowed_scopes", sa.Text(), nullable=False),
        sa.Column("_default_scopes", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("client_id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        op.f("ix_client_client_secret"), "client", ["client_secret"], unique=True
    )
    op.create_table(
        "compute_access",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.Column("instances", sa.Integer(), nullable=True),
        sa.Column("cores", sa.Integer(), nullable=True),
        sa.Column("ram", sa.BigInteger(), nullable=True),
        sa.Column("floating_ips", sa.Integer(), nullable=True),
        sa.Column(
            "additional_info", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.ForeignKeyConstraint(["group_id"], ["Group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["cloud_provider.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "ga4gh_visa_v1",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("ga4gh_visa", sa.Text(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("asserted", sa.BigInteger(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "google_proxy_group_to_google_bucket_access_group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proxy_group_id", sa.String(), nullable=False),
        sa.Column("access_group_id", sa.Integer(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["access_group_id"], ["google_bucket_access_group.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["proxy_group_id"], ["google_proxy_group.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "google_service_account",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("google_unique_id", sa.String(), nullable=False),
        sa.Column("client_id", sa.String(length=40), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("google_project_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "hmac_keypair",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("access_key", sa.String(), nullable=True),
        sa.Column("secret_key", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("expire", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "hmac_keypair_archive",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("access_key", sa.String(), nullable=True),
        sa.Column("secret_key", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("expire", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "iss_sub_pair_to_user",
        sa.Column("iss", sa.String(), nullable=False),
        sa.Column("sub", sa.String(), nullable=False),
        sa.Column("fk_to_User", sa.Integer(), nullable=False),
        sa.Column(
            "extra_info",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(["fk_to_User"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("iss", "sub"),
    )
    op.create_table(
        "s3credential",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("access_key", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("expire", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "service_account_to_google_bucket_access_group",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("service_account_id", sa.Integer(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=True),
        sa.Column("access_group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["access_group_id"], ["google_bucket_access_group.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["service_account_id"], ["user_service_account.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "storage_access",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.Column("max_objects", sa.BigInteger(), nullable=True),
        sa.Column("max_size", sa.BigInteger(), nullable=True),
        sa.Column("max_buckets", sa.Integer(), nullable=True),
        sa.Column(
            "additional_info", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.CheckConstraint(
            "user_id is NULL or group_id is NULL or project_id is NULL",
            name="check_storage_subject",
        ),
        sa.ForeignKeyConstraint(["group_id"], ["Group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["cloud_provider.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "tag",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "key"),
    )
    op.create_table(
        "upstream_refresh_token",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_google_account",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "user_to_bucket",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("bucket_id", sa.Integer(), nullable=True),
        sa.Column("privilege", postgresql.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(["bucket_id"], ["bucket.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_to_group",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("roles", postgresql.ARRAY(sa.String()), nullable=True),
        sa.ForeignKeyConstraint(["group_id"], ["Group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "group_id"),
    )
    op.create_table(
        "certificate",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("application_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=40), nullable=True),
        sa.Column("extension", sa.String(), nullable=True),
        sa.Column("data", sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(
            ["application_id"], ["application.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "google_service_account_key",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("service_account_id", sa.Integer(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=True),
        sa.Column("private_key", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["service_account_id"], ["google_service_account.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_google_account_to_proxy_group",
        sa.Column("user_google_account_id", sa.Integer(), nullable=False),
        sa.Column("proxy_group_id", sa.String(), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["proxy_group_id"], ["google_proxy_group.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_google_account_id"], ["user_google_account.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("user_google_account_id", "proxy_group_id"),
    )


def downgrade():
    op.drop_table("user_google_account_to_proxy_group")
    op.drop_table("google_service_account_key")
    op.drop_table("certificate")
    op.drop_table("user_to_group")
    op.drop_table("user_to_bucket")
    op.drop_table("user_google_account")
    op.drop_table("upstream_refresh_token")
    op.drop_table("tag")
    op.drop_table("storage_access")
    op.drop_table("service_account_to_google_bucket_access_group")
    op.drop_table("s3credential")
    op.drop_table("iss_sub_pair_to_user")
    op.drop_table("hmac_keypair_archive")
    op.drop_table("hmac_keypair")
    op.drop_table("google_service_account")
    op.drop_table("google_proxy_group_to_google_bucket_access_group")
    op.drop_table("ga4gh_visa_v1")
    op.drop_table("compute_access")
    op.drop_index(op.f("ix_client_client_secret"), table_name="client")
    op.drop_table("client")
    op.drop_table("authorization_code")
    op.drop_table("application")
    op.drop_index(
        "unique_user_project_id",
        table_name="access_privilege",
        postgresql_where=sa.text("group_id is NULL"),
    )
    op.drop_index(
        "unique_user_group_id",
        table_name="access_privilege",
        postgresql_where=sa.text("project_id is NULL"),
    )
    op.drop_index(
        "unique_group_project_id",
        table_name="access_privilege",
        postgresql_where=sa.text("user_id is NULL"),
    )
    op.drop_table("access_privilege")
    op.drop_table("project_to_bucket")
    op.drop_table("google_bucket_access_group")
    op.drop_table("User")
    op.drop_table("service_account_access_privilege")
    op.drop_table("department")
    op.drop_table("bucket")
    op.drop_table("user_service_account")
    op.drop_table("user_refresh_token")
    op.drop_table("user_audit_logs")
    op.drop_table("project")
    op.drop_table("organization")
    op.drop_table("identity_provider")
    op.drop_table("google_proxy_group")
    op.drop_table("gcp_assume_role_cache")
    op.drop_table("ga4gh_passport_cache")
    op.drop_table("event_log")
    op.drop_table("cloud_provider")
    op.drop_table("cert_audit_logs")
    op.drop_table("blacklisted_token")
    op.drop_table("authorization_provider")
    op.drop_table("assume_role_cache")
    op.drop_table("Group")
