"""Database connections, and `setup()` which creates the roles, tables and grants.

Run `python -m p14g_example.db` (or `make setup`) to (re)create everything.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg

from .policy import UNTRUSTED_ROLE, Ctx, policy

__all__ = 'ADMIN_URL', 'OWNER_URL', 'UNTRUSTED_URL', 'setup'

_HOST = os.getenv('EXAMPLE_PG_HOST', '127.0.0.1:54331')
_DB = os.getenv('EXAMPLE_PG_DB', 'example')
# superuser, only for `setup()`
ADMIN_URL = os.getenv('EXAMPLE_ADMIN_URL', f'postgres://postgres:postgres@{_HOST}/{_DB}')
# owns the tables; the server uses it to look up API keys and write the audit log
OWNER_URL = os.getenv('EXAMPLE_OWNER_URL', f'postgres://example_owner:owner@{_HOST}/{_DB}')
# runs p14g's output
UNTRUSTED_URL = os.getenv('EXAMPLE_UNTRUSTED_URL', f'postgres://{UNTRUSTED_ROLE}:untrusted@{_HOST}/{_DB}')

SCHEMA_SQL = Path(__file__).parent.parent / 'sql' / 'schema.sql'


async def setup() -> list[str]:
    """Create the roles, schema and seed data, then grant the untrusted role what the policy allows.

    Returns the grant statements that were run.
    """
    conn = await asyncpg.connect(ADMIN_URL)
    try:
        async with conn.transaction():
            await conn.execute(SCHEMA_SQL.read_text())
            # The grants come from the policy, so the database and p14g cannot drift apart. The context is only
            # used to learn which columns `extra` sets, so any org will do.
            grants = policy.grants(UNTRUSTED_ROLE, context=Ctx(org_id=0, user_id=0))
            await conn.execute('set role example_owner')
            for grant in grants:
                await conn.execute(grant)
            await conn.execute('reset role')
    finally:
        await conn.close()
    return grants


if __name__ == '__main__':
    for g in asyncio.run(setup()):
        print(g)
