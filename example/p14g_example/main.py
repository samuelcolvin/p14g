"""A FastAPI server that runs SQL written by its users, who are not trusted.

Each request goes through three layers:

1. p14g checks the statement against `policy` and rewrites it: tables and columns outside the policy are refused,
   `org_id = <caller's org>` is added for every multi-tenant table, `org_id` is set on inserts, and a `LIMIT` is added.
2. The statement runs as `example_untrusted`, which has only the grants `policy.grants()` returned.
3. Row-level security on the multi-tenant tables reads `app.org_id`, which is set for the transaction only.
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from p14g import Delete, Insert, P14gError, Select
from pydantic import BaseModel

from .db import OWNER_URL, UNTRUSTED_URL
from .policy import Ctx, policy, rules

__all__ = ('app',)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with (
        asyncpg.create_pool(OWNER_URL, min_size=1, max_size=5) as owner_pool,
        asyncpg.create_pool(UNTRUSTED_URL, min_size=1, max_size=10) as untrusted_pool,
    ):
        app.state.owner_pool = owner_pool
        app.state.untrusted_pool = untrusted_pool
        yield


app = FastAPI(title='p14g example', lifespan=lifespan)
bearer = HTTPBearer()


def owner_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.owner_pool


def untrusted_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.untrusted_pool


async def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    pool: Annotated[asyncpg.Pool, Depends(owner_pool)],
) -> Ctx:
    key_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    row = await pool.fetchrow(
        'select u.id, u.org_id from app.api_keys k join app.users u on u.id = k.user_id where k.key_hash = $1',
        key_hash,
    )
    if row is None:
        raise HTTPException(status_code=401, detail='invalid API key')
    return Ctx(org_id=row['org_id'], user_id=row['id'])


class Query(BaseModel):
    sql: str


class QueryResult(BaseModel):
    kind: Literal['select', 'insert', 'update', 'delete']
    sql: str
    """The statement as p14g rewrote it, which is what ran."""
    status: str
    """Postgres's command tag, e.g. `UPDATE 2`."""
    columns: list[str]
    rows: list[list[Any]]


class QueryError(BaseModel):
    error: str
    message: str
    line: int | None = None
    column: int | None = None
    sql: str | None = None


@app.post('/query', responses={400: {'model': QueryError}})
async def run_query(
    query: Query,
    ctx: Annotated[Ctx, Depends(current_user)],
    untrusted: Annotated[asyncpg.Pool, Depends(untrusted_pool)],
    owner: Annotated[asyncpg.Pool, Depends(owner_pool)],
) -> QueryResult:
    try:
        safe = policy.rewrite(query.sql, context=ctx)
    except P14gError as e:
        await audit(owner, ctx, query.sql, None, f'p14g {e.kind}')
        raise HTTPException(
            status_code=400,
            detail=QueryError(error=e.kind, message=e.message, line=e.line, column=e.column).model_dump(),
        ) from e

    try:
        async with untrusted.acquire() as conn, conn.transaction(readonly=safe.kind == 'select'):
            # `true`: the setting lasts until the end of this transaction, so it never leaks to the next request on
            # this pooled connection. p14g does not allow `set_config` in the statement, so it cannot change it.
            await conn.execute("select set_config('app.org_id', $1, true)", str(ctx.org_id))
            stmt = await conn.prepare(safe.sql)
            records = await stmt.fetch()
            columns = [a.name for a in stmt.get_attributes()]
            status = stmt.get_statusmsg()
    except asyncpg.PostgresError as e:
        # Only the SQLSTATE goes back: messages can quote values from rows the caller may not see, e.g. a unique
        # violation's "Key (email)=(...) already exists".
        await audit(owner, ctx, query.sql, safe.sql, f'postgres {e.sqlstate}')
        raise HTTPException(
            status_code=400,
            detail=QueryError(error='database', message=f'SQLSTATE {e.sqlstate}', sql=safe.sql).model_dump(),
        ) from e

    await audit(owner, ctx, query.sql, safe.sql, None)
    return QueryResult(
        kind=safe.kind,
        sql=safe.sql,
        status=status,
        columns=columns,
        rows=[[to_json(v) for v in r.values()] for r in records],
    )


class TableAccess(BaseModel):
    table: str
    kind: Literal['select', 'insert', 'update', 'delete']
    columns: list[str] | None
    """`None` means every column."""


@app.get('/schema')
async def schema(_: Annotated[Ctx, Depends(current_user)]) -> list[TableAccess]:
    """What the policy lets a caller do, e.g. to give to an LLM that writes the SQL."""
    out: list[TableAccess] = []
    for rule in rules:
        if isinstance(rule, Delete):
            out.append(TableAccess(table=rule.table, kind='delete', columns=None))
        else:
            kind = 'select' if isinstance(rule, Select) else 'insert' if isinstance(rule, Insert) else 'update'
            out.append(TableAccess(table=rule.table, kind=kind, columns=rule.columns))
    return out


async def audit(pool: asyncpg.Pool, ctx: Ctx, sql_in: str, sql_out: str | None, error: str | None) -> None:
    await pool.execute(
        'insert into app.audit_log (org_id, user_id, sql_in, sql_out, error) values ($1, $2, $3, $4, $5)',
        ctx.org_id,
        ctx.user_id,
        sql_in,
        sql_out,
        error,
    )


def to_json(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value
