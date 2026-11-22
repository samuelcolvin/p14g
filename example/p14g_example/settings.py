"""Settings, from environment variables prefixed `EXAMPLE_` or a `.env` file, e.g. `EXAMPLE_OWNER_DSN=postgres://...`.

The defaults match the database `make db` starts and the roles `schema.sql` creates.
"""

from __future__ import annotations

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = 'Settings', 'settings'


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='EXAMPLE_', env_file='.env', extra='ignore')

    admin_dsn: PostgresDsn = PostgresDsn('postgres://postgres:postgres@127.0.0.1:54331/example')
    """A superuser, used only by `setup()`."""
    owner_dsn: PostgresDsn = PostgresDsn('postgres://example_owner:owner@127.0.0.1:54331/example')
    """Owns the tables. The server uses it to write the audit log."""
    untrusted_dsn: PostgresDsn = PostgresDsn('postgres://example_untrusted:untrusted@127.0.0.1:54331/example')
    """Runs p14g's output. The role name must match `UNTRUSTED_ROLE` in policy.py."""

    owner_pool_size: int = 5
    untrusted_pool_size: int = 10

    max_rows: int = 1000
    """Cap on the rows a `SELECT` returns; p14g adds or lowers its `LIMIT`."""


settings = Settings()
