"""A FastAPI server that runs SQL written by its users, who are not trusted.

There is no authentication: every request runs as Anne, in org `ORG_ID`. Each one goes through three layers:

1. p14g checks the statement against `policy` and rewrites it: tables and columns outside the policy are refused,
   `org_id = ORG_ID` is added for every multi-tenant table, `org_id` is set on inserts, and a `LIMIT` is added.
2. The statement runs as `example_untrusted`, which has only the grants `policy.grants()` returned. The pool logs
   in as `example_authenticator`, which has no privileges, and switches to it for each transaction.
3. Row-level security on the multi-tenant tables reads `app.org_id`, which is set for the transaction only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request
from p14g import P14gError
from pydantic import BaseModel

from .policy import ORG_ID, UNTRUSTED_ROLE, policy
from .settings import settings

__all__ = ('app',)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with (
        asyncpg.create_pool(str(settings.owner_dsn), min_size=1, max_size=settings.owner_pool_size) as owner_pool,
        asyncpg.create_pool(
            str(settings.authenticator_dsn), min_size=1, max_size=settings.authenticator_pool_size
        ) as untrusted_pool,
    ):
        app.state.owner_pool = owner_pool
        app.state.untrusted_pool = untrusted_pool
        yield


app = FastAPI(title='p14g example', lifespan=lifespan)


def owner_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.owner_pool


def untrusted_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.untrusted_pool


class Query(BaseModel):
    sql: str


class QueryResult(BaseModel):
    sql: str
    """The statement as p14g rewrote it, which is what ran."""
    status: str
    """Postgres's command tag, e.g. `UPDATE 2`."""
    rows: list[dict[str, Any]]


class QueryError(BaseModel):
    error: str
    message: str
    line: int | None = None
    column: int | None = None
    sql: str | None = None


@app.post('/query', responses={400: {'model': QueryError}})
async def run_query(
    query: Query,
    untrusted: Annotated[asyncpg.Pool, Depends(untrusted_pool)],
    owner: Annotated[asyncpg.Pool, Depends(owner_pool)],
) -> QueryResult:
    try:
        safe = policy.rewrite(query.sql, context=ORG_ID)
    except P14gError as e:
        await audit(owner, query.sql, None, f'p14g {e.kind}')
        raise HTTPException(
            status_code=400,
            detail=QueryError(error=e.kind, message=e.message, line=e.line, column=e.column).model_dump(),
        ) from e

    try:
        async with untrusted.acquire() as conn, conn.transaction(readonly=safe.kind == 'select'):
            # The pool logs in as `example_authenticator`, which has no privileges. Switch to the role that has the
            # grants, and set the org that row-level security reads. `true` makes both last until the end of this
            # transaction, so neither stays on the pooled connection for the next request. This is `SET LOCAL ROLE`,
            # but takes the role as a parameter, so an app with many roles can pick one per request.
            # p14g rejects `SET`, `RESET` and `set_config` in the statement, so it cannot change either.
            await conn.execute(
                "select set_config('role', $1, true), set_config('app.org_id', $2, true)", UNTRUSTED_ROLE, ORG_ID
            )
            stmt = await conn.prepare(safe.sql)
            records = await stmt.fetch()
            status = stmt.get_statusmsg()
    except asyncpg.PostgresError as e:
        # Only the SQLSTATE goes back: messages can quote values from rows Anne may not see, e.g. a unique
        # violation's "Key (email)=(...) already exists".
        await audit(owner, query.sql, safe.sql, f'postgres {e.sqlstate}')
        raise HTTPException(
            status_code=400,
            detail=QueryError(error='database', message=f'SQLSTATE {e.sqlstate}', sql=safe.sql).model_dump(),
        ) from e

    await audit(owner, query.sql, safe.sql, None)
    return QueryResult(sql=safe.sql, status=status, rows=[dict(r) for r in records])


async def audit(pool: asyncpg.Pool, sql_in: str, sql_out: str | None, error: str | None) -> None:
    await pool.execute(
        'insert into app.audit_log (org_id, sql_in, sql_out, error) values ($1, $2, $3, $4)',
        ORG_ID,
        sql_in,
        sql_out,
        error,
    )
