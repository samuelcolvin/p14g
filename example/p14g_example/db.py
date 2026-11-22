"""`setup()`, which creates the roles, tables and grants.

Run `python -m p14g_example.db` (or `make setup`) to (re)create everything.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import asyncpg

from .policy import ORG_ID, UNTRUSTED_ROLE, policy
from .settings import settings

__all__ = ('setup',)

SCHEMA_SQL = Path(__file__).parent.parent / 'sql' / 'schema.sql'


async def setup() -> list[str]:
    """Create the roles, schema and seed data, then grant the untrusted role what the policy allows.

    Returns the grant statements that were run.
    """
    conn = await asyncpg.connect(str(settings.admin_dsn))
    try:
        async with conn.transaction():
            await conn.execute(SCHEMA_SQL.read_text())
            # The grants come from the policy, so the database and p14g cannot drift apart. The context is used to
            # learn which columns `extra` sets.
            grants = policy.grants(UNTRUSTED_ROLE, context=ORG_ID)
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
