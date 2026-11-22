"""What untrusted SQL may do, as a p14g policy.

The same rules are enforced by Postgres: `setup` runs `policy.grants()` for the role that executes the output, and
`sql/schema.sql` puts row-level security with the same condition as `by_org` on every multi-tenant table.

`api_keys`, `invoices` and `audit_log` are not mentioned, so a statement that names them is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass

from p14g import Delete, Insert, Policy, Select, Update

__all__ = 'UNTRUSTED_ROLE', 'Ctx', 'policy', 'rules'

UNTRUSTED_ROLE = 'example_untrusted'


@dataclass(frozen=True)
class Ctx:
    """Who is running the statement, from their API key."""

    org_id: int
    user_id: int


def by_org(ctx: Ctx) -> tuple[str, dict[str, int]]:
    return 'org_id = :org_id', {'org_id': ctx.org_id}


def own_org(ctx: Ctx) -> tuple[str, dict[str, int]]:
    return 'id = :org_id', {'org_id': ctx.org_id}


def set_org(ctx: Ctx) -> dict[str, int]:
    return {'org_id': ctx.org_id}


PROJECT_COLUMNS = ['id', 'name', 'country_code', 'created_at']
TASK_COLUMNS = ['id', 'project_id', 'assignee_id', 'title', 'status', 'due_date', 'created_at']

rules: list[Select[Ctx] | Insert[Ctx] | Update[Ctx] | Delete[Ctx]] = [
    # reference data, every row
    Select('countries'),
    # the caller's own organisation, without `plan` or `stripe_customer_id`
    Select('organisations', columns=['id', 'name'], filter=own_org),
    # people in the caller's organisation, never `password_hash`
    Select('users', columns=['id', 'name', 'email', 'created_at'], filter=by_org),
    # `org_id` is left out of the columns: the filter and `extra` deal with it, so a statement can neither read
    # nor set it
    Select('projects', columns=PROJECT_COLUMNS, filter=by_org),
    Insert('projects', columns=['name', 'country_code'], extra=set_org),
    Update('projects', columns=['name', 'country_code'], filter=by_org),
    Delete('projects', filter=by_org),
    Select('tasks', columns=TASK_COLUMNS, filter=by_org),
    Insert('tasks', columns=['project_id', 'assignee_id', 'title', 'status', 'due_date'], extra=set_org),
    Update('tasks', columns=['assignee_id', 'title', 'status', 'due_date'], filter=by_org),
    Delete('tasks', filter=by_org),
]

policy: Policy[Ctx] = Policy(
    *rules,
    # table names in statements are written `app.name`, never resolved through the search_path
    default_schema='app',
    qualify_builtins=True,
    max_rows=1000,
)
