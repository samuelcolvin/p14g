"""End-to-end tests against the Postgres from `make db`. The database is recreated at the start of the run."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import asyncpg
import pytest
from fastapi.testclient import TestClient

from p14g_example.db import setup
from p14g_example.main import app
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


def untrusted(sql: str, org_id: int | None) -> Any:
    """Run `sql` as the untrusted role directly, without p14g, to check what Postgres enforces by itself."""

    async def run() -> Any:
        conn = await asyncpg.connect(str(settings.untrusted_dsn))
        try:
            async with conn.transaction():
                if org_id is not None:
                    await conn.execute("select set_config('app.org_id', $1, true)", str(org_id))
                return await conn.fetch(sql)
        finally:
            await conn.close()

    return asyncio.run(run())


def test_tasks_only_own_org(client: TestClient):
    r = query(client, 'select * from tasks order by id')
    assert r['sql'] == (
        'SELECT tasks.id, tasks.project_id, tasks.assignee_id, tasks.title, tasks.status, tasks.due_date, '
        'tasks.created_at\n'
        'FROM (SELECT tasks.id, tasks.project_id, tasks.assignee_id, tasks.title, tasks.status, tasks.due_date, '
        'tasks.created_at FROM app.tasks WHERE tasks.org_id = 1) AS tasks\n'
        'ORDER BY tasks.id\n'
        'LIMIT 1000'
    )
    assert r['columns'] == ['id', 'project_id', 'assignee_id', 'title', 'status', 'due_date', 'created_at']
    assert [row[3] for row in r['rows']] == ['Order wheels', 'Fit rocket', 'Source magnet']


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
    assert r['rows'] == [['Giant magnet', 'United Kingdom', 1], ['Rocket skates', 'United States', 2]]


def test_own_organisation(client: TestClient):
    assert query(client, 'select * from organisations')['rows'] == [[1, 'Acme']]
    r = query(client, 'select stripe_customer_id from organisations')
    assert r['error'] == 'denied'


@pytest.mark.parametrize('table', ['api_keys', 'invoices', 'audit_log'])
def test_blocked_tables(client: TestClient, table: str):
    r = query(client, f'select * from {table}')
    assert r['error'] == 'denied', r


def test_password_hash(client: TestClient):
    assert query(client, 'select password_hash from users')['error'] == 'denied'
    r = query(client, 'select * from users order by id')
    assert r['columns'] == ['id', 'name', 'email', 'created_at']
    assert [row[1] for row in r['rows']] == ['Anne', 'Bob']


def test_org_id_hidden(client: TestClient):
    """The filter uses `org_id`, but statements may not read or set it."""
    assert query(client, 'select org_id from tasks')['error'] == 'denied'
    assert query(client, "insert into tasks (org_id, project_id, title) values (2, 3, 'x')")['error'] == 'denied'
    assert query(client, 'update tasks set org_id = 2 where id = 1')['error'] == 'denied'


@pytest.mark.parametrize(
    'sql',
    [
        'drop table tasks',
        "select set_config('app.org_id', '2', false)",
        'select * from tasks; select * from api_keys',
        'select * from pg_catalog.pg_shadow',
        "select pg_read_file('/etc/passwd')",
        'select pg_sleep(10)',
    ],
)
def test_rejected(client: TestClient, sql: str):
    assert query(client, sql)['error'] in ('denied', 'unsupported', 'parse')


def test_insert_sets_org(client: TestClient):
    r = query(client, "insert into tasks (project_id, title) values (2, 'Polish magnet') returning id, title")
    assert r['kind'] == 'insert'
    assert r['status'] == 'INSERT 0 1'
    assert 'org_id' in r['sql']
    (task_id, title) = r['rows'][0]
    assert title == 'Polish magnet'

    assert query(client, f'delete from tasks where id = {task_id}')['status'] == 'DELETE 1'


def test_insert_into_other_orgs_project(client: TestClient):
    """Project 3 belongs to Globex. The composite foreign key on (org_id, project_id) refuses it."""
    r = query(client, "insert into tasks (project_id, title) values (3, 'sneaky')")
    assert r == {
        'error': 'database',
        'message': 'SQLSTATE 23503',
        'line': None,
        'column': None,
        'sql': "INSERT INTO app.tasks (project_id, title, org_id)\nVALUES (3, 'sneaky', 1)",
    }


def test_update_where_true(client: TestClient):
    r = query(client, "update tasks set status = 'done' where true")
    assert r['status'] == 'UPDATE 3'
    globex = untrusted('select status from app.tasks order by id', 2)
    assert [r['status'] for r in globex] == ['done', 'doing', 'todo']


def test_unfiltered_update_rejected(client: TestClient):
    assert query(client, "update tasks set status = 'done'")['error'] == 'denied'


def test_division_probe(client: TestClient):
    """The probe from p14g's README: with RLS it never sees Globex's task 4, so there is no division by zero."""
    r = query(client, 'select id from tasks where 1 / (id - 4) > -100')
    assert r['rows'] == [[1], [2], [3]]


def test_audit_log(client: TestClient):
    query(client, 'select 1 as one')

    async def last() -> asyncpg.Record | None:
        conn = await asyncpg.connect(str(settings.admin_dsn))
        try:
            return await conn.fetchrow('select org_id, sql_in from app.audit_log order by id desc limit 1')
        finally:
            await conn.close()

    assert dict(asyncio.run(last()) or {}) == {'org_id': 1, 'sql_in': 'select 1 as one'}


# Without p14g in front: what Postgres enforces on its own


def test_db_rls_without_setting():
    """No `app.org_id` set: RLS shows nothing."""
    assert untrusted('select id from app.tasks', None) == []


def test_db_rls_hides_other_org():
    rows = untrusted('select title from app.tasks order by id', 2)
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
        untrusted(sql, 1)


def test_db_with_check():
    """RLS's `WITH CHECK` refuses a row for another org even if the statement sets `org_id` itself."""
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match='row-level security'):
        untrusted("insert into app.projects (org_id, name) values (2, 'x')", 1)


def test_db_statement_timeout():
    with pytest.raises(asyncpg.QueryCanceledError):
        untrusted('select pg_sleep(5)', 1)
