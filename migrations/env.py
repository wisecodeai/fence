from alembic import context
from logging.config import fileConfig
import os
from sqlalchemy import engine_from_config, pool

from userdatamodel import Base

from fence.config import config as fence_config
from fence.settings import CONFIG_SEARCH_FOLDERS


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

fence_config.load(
    config_path=os.environ.get("TEST_CONFIG_PATH"),  # for tests
    search_folders=CONFIG_SEARCH_FOLDERS,  # for deployments
)
config.set_main_option("sqlalchemy.url", str(fence_config["DB"]))


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            print("Locking database to ensure only 1 migration runs at a time")
            connection.execute("SELECT pg_advisory_xact_lock(100);")
            context.run_migrations()
        print("Releasing database lock")


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
