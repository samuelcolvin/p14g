"""End-to-end tests against the Postgres from `make db`. The database is recreated at the start of the run."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from uuid import UUID

import asyncpg
import pytest
from fastapi.testclient import TestClient

from p14g_example.db import setup
from p14g_example.main import app
from p14g_example.policy import ORG_ID, UNTRUSTED_ROLE
from p14g_example.settings import settings


async def _reachable() -> bool:
    try:
        conn = await asyncpg.connect(str(settings.admin_dsn), timeout=2)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


@pytest.fixture(scope='session')
def client() -> Iterator[TestClient]:
    if not asyncio.run(_reachable()):
        pytest.skip(f'Postgres not reachable at {settings.admin_dsn}, run `make db`')
    asyncio.run(setup())
    with TestClient(app) as c:
        yield c


def query(client: TestClient, sql: str) -> dict[str, Any]:
    r = client.post('/query', json={'sql': sql})
    body = r.json()
    if r.status_code == 400:
        return body['detail']
    assert r.status_code == 200, body
    return body


def untrusted(sql: str, org_id: str | None, role: str | None = UNTRUSTED_ROLE) -> Any:
    """Run `sql` as the server does, but without p14g, to check what Postgres enforces by itself.

    It connects as the authenticator and switches to `role` for the transaction, unless `role` is `None`.
    """

    async def run() -> Any:
        conn = await asyncpg.connect(str(settings.authenticator_dsn))
        try:
            async with conn.transaction():
                if role is not None:
                    await conn.execute("select set_config('role', $1, true)", role)
                if org_id is not None:
                    await conn.execute("select set_config('app.org_id', $1, true)", org_id)
                return await conn.fetch(sql)
        finally:
            await conn.close()

    return asyncio.run(run())


GLOBEX = '10000000-0000-4000-8000-000000000002'
GIANT_MAGNET = '30000000-0000-4000-8000-000000000002'  # an Acme project
HAMMOCK_FACTORY = '30000000-0000-4000-8000-000000000003'  # a Globex project


def test_tasks_only_own_org(client: TestClient):
    r = query(client, 'select * from tasks order by id')
    assert r['sql'] == (
        'SELECT tasks.id, tasks.project_id, tasks.assignee_id, tasks.title, tasks.status, tasks.due_date, '
        'tasks.created_at\n'
        'FROM (SELECT tasks.id, tasks.project_id, tasks.assignee_id, tasks.title, tasks.status, tasks.due_date, '
        f"tasks.created_at FROM app.tasks WHERE tasks.org_id = '{ORG_ID}') AS tasks\n"
        'ORDER BY tasks.id\n'
        'LIMIT 1000'
    )
    assert list(r['rows'][0]) == ['id', 'project_id', 'assignee_id', 'title', 'status', 'due_date', 'created_at']
    assert [row['title'] for row in r['rows']] == ['Order wheels', 'Fit rocket', 'Source magnet']


def test_join(client: TestClient):
    r = query(
        client,
        """
        select p.name, c.name as country, count(*) as tasks
        from projects p
        join countries c on c.code = p.country_code
        join tasks t on t.project_id = p.id
        group by p.name, c.name
        order by p.name
        """,
    )
    assert r['rows'] == [
        {'name': 'Giant magnet', 'country': 'United Kingdom', 'tasks': 1},
        {'name': 'Rocket skates', 'country': 'United States', 'tasks': 2},
    ]


def test_own_organisation(client: TestClient):
    assert query(client, 'select * from organisations')['rows'] == [{'id': ORG_ID, 'name': 'Acme'}]
    r = query(client, 'select stripe_customer_id from organisations')
    assert r['error'] == 'denied'


@pytest.mark.parametrize('table', ['api_keys', 'invoices', 'audit_log'])
def test_blocked_tables(client: TestClient, table: str):
    r = query(client, f'select * from {table}')
    assert r['error'] == 'denied', r


def test_password_hash(client: TestClient):
    assert query(client, 'select password_hash from users')['error'] == 'denied'
    r = query(client, 'select * from users order by id')
    assert list(r['rows'][0]) == ['id', 'name', 'email', 'created_at']
    assert [row['name'] for row in r['rows']] == ['Anne', 'Bob']


def test_org_id_hidden(client: TestClient):
    """The filter uses `org_id`, but statements may not read or set it."""
    assert query(client, 'select org_id from tasks')['error'] == 'denied'
    sql = f"insert into tasks (org_id, project_id, title) values ('{GLOBEX}', '{HAMMOCK_FACTORY}', 'x')"
    assert query(client, sql)['error'] == 'denied'
    assert query(client, f"update tasks set org_id = '{GLOBEX}' where true")['error'] == 'denied'


@pytest.mark.parametrize(
    'sql',
    [
        'drop table tasks',
        f"select set_config('app.org_id', '{GLOBEX}', false)",
        'select * from tasks; select * from api_keys',
        'select * from pg_catalog.pg_shadow',
        "select pg_read_file('/etc/passwd')",
        'select pg_sleep(10)',
    ],
)
def test_rejected(client: TestClient, sql: str):
    assert query(client, sql)['error'] in ('denied', 'unsupported', 'parse')


def test_insert_sets_org(client: TestClient):
    r = query(
        client, f"insert into tasks (project_id, title) values ('{GIANT_MAGNET}', 'Polish magnet') returning id, title"
    )
    assert r['status'] == 'INSERT 0 1'
    assert 'org_id' in r['sql']
    task_id = r['rows'][0]['id']
    assert r['rows'][0]['title'] == 'Polish magnet'

    assert query(client, f"delete from tasks where id = '{task_id}'")['status'] == 'DELETE 1'


def test_insert_into_other_orgs_project(client: TestClient):
    """The composite foreign key on (org_id, project_id) refuses a Globex project."""
    r = query(client, f"insert into tasks (project_id, title) values ('{HAMMOCK_FACTORY}', 'sneaky')")
    assert r == {
        'error': 'database',
        'message': 'SQLSTATE 23503',
        'line': None,
        'column': None,
        'sql': f"INSERT INTO app.tasks (project_id, title, org_id)\nVALUES ('{HAMMOCK_FACTORY}', 'sneaky', '{ORG_ID}')",
    }


def test_update_where_true(client: TestClient):
    r = query(client, "update tasks set status = 'done' where true")
    assert r['status'] == 'UPDATE 3'
    globex = untrusted('select status from app.tasks order by id', GLOBEX)
    assert [r['status'] for r in globex] == ['done', 'doing', 'todo']


def test_unfiltered_update_rejected(client: TestClient):
    assert query(client, "update tasks set status = 'done'")['error'] == 'denied'


def test_division_probe(client: TestClient):
    """Like the probe in p14g's README: with RLS it never sees Globex's "Classified" task, so no division by zero."""
    r = query(client, "select title from tasks where 1 / (strpos(title, 'Classified') - 1) < 0 order by id")
    assert [row['title'] for row in r['rows']] == ['Order wheels', 'Fit rocket', 'Source magnet']


def test_audit_log(client: TestClient):
    query(client, 'select 1 as one')

    async def last() -> asyncpg.Record | None:
        conn = await asyncpg.connect(str(settings.admin_dsn))
        try:
            return await conn.fetchrow('select org_id, sql_in from app.audit_log order by id desc limit 1')
        finally:
            await conn.close()

    assert dict(asyncio.run(last()) or {}) == {'org_id': UUID(ORG_ID), 'sql_in': 'select 1 as one'}


# Without p14g in front: what Postgres enforces on its own


def test_db_rls_without_setting():
    """No `app.org_id` set: RLS shows nothing."""
    assert untrusted('select id from app.tasks', None) == []


def test_db_rls_hides_other_org():
    rows = untrusted('select title from app.tasks order by id', GLOBEX)
    assert [r['title'] for r in rows] == ['Find a site', 'Hire weavers', 'Classified']


@pytest.mark.parametrize(
    'sql',
    [
        'select * from app.api_keys',
        'select * from app.invoices',
        'select password_hash from app.users',
        'select plan from app.organisations',
        'create table app.mine (id int)',
        'create table public.mine (id int)',
    ],
)
def test_db_permission_denied(sql: str):
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        untrusted(sql, ORG_ID)


def test_db_with_check():
    """RLS's `WITH CHECK` refuses a row for another org even if the statement sets `org_id` itself."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match='row-level security'):
        untrusted(f"insert into app.projects (org_id, name) values ('{GLOBEX}', 'x')", ORG_ID)


def test_db_limits():
    """The limits are on the authenticator, and still apply after switching role."""
    rows = untrusted(
        "select current_setting('work_mem') as w, current_setting('temp_file_limit') as t, "
        "current_setting('max_parallel_workers_per_gather') as p",
        ORG_ID,
    )
    assert [dict(r) for r in rows] == [{'w': '4MB', 't': '100MB', 'p': '0'}]


def test_db_temp_file_limit():
    with pytest.raises(asyncpg.ConfigurationLimitExceededError):
        untrusted('select g from generate_series(1, 10000000) g order by g desc', ORG_ID)


def test_db_statement_timeout():
    with pytest.raises(asyncpg.QueryCanceledError):
        untrusted('select pg_sleep(5)', ORG_ID)


def test_db_authenticator_has_no_privileges():
    """Without switching role, the connection the pool opens can read nothing."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        untrusted('select * from app.countries', ORG_ID, role=None)


def test_db_authenticator_cannot_become_owner():
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        untrusted('select 1', ORG_ID, role='example_owner')


def test_db_role_ends_with_transaction():
    async def run() -> tuple[str, str]:
        conn = await asyncpg.connect(str(settings.authenticator_dsn))
        try:
            async with conn.transaction():
                await conn.execute("select set_config('role', $1, true)", UNTRUSTED_ROLE)
                inside = await conn.fetchval('select current_user')
            outside = await conn.fetchval('select current_user')
        finally:
            await conn.close()
        return inside, outside

    assert asyncio.run(run()) == (UNTRUSTED_ROLE, 'example_authenticator')
