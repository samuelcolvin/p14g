"""What untrusted SQL may do, as a p14g policy.

The same rules are enforced by Postgres: `setup` runs `policy.grants()` for the role that executes the output, and
`schema.sql` puts row-level security with the same condition as `by_org` on every multi-tenant table.

`api_keys`, `invoices` and `audit_log` are not mentioned, so a statement that names them is rejected.
"""

from __future__ import annotations

from p14g import Delete, Insert, Policy, Select, Update

from .settings import settings

__all__ = 'ORG_ID', 'UNTRUSTED_ROLE', 'policy'

# created by schema.sql, so not a setting
UNTRUSTED_ROLE = 'example_untrusted'

# The untrusted user is always Anne, who is in Acme. `main.py` passes this to `rewrite()` as the context; a real app
# would take the org from the logged-in user.
ORG_ID = '10000000-0000-4000-8000-000000000001'


def by_org(org_id: str) -> tuple[str, dict[str, str]]:
    """The same condition as the row-level security in schema.sql."""
    return 'org_id = :org_id', {'org_id': org_id}


def own_org(org_id: str) -> tuple[str, dict[str, str]]:
    return 'id = :org_id', {'org_id': org_id}


def set_org(org_id: str) -> dict[str, str]:
    return {'org_id': org_id}


policy = Policy(
    # reference data, every row
    Select('countries', columns=['code', 'name']),
    # Anne's own organisation, without `plan` or `stripe_customer_id`
    Select('organisations', columns=['id', 'name'], filter=own_org),
    # people in Anne's organisation, never `password_hash`
    Select('users', columns=['id', 'name', 'email', 'created_at'], filter=by_org),
    # `org_id` is left out of the columns: the filter and `extra` deal with it, so a statement can neither read
    # nor set it
    Select('projects', columns=['id', 'name', 'country_code', 'created_at'], filter=by_org),
    Insert('projects', columns=['name', 'country_code'], extra=set_org),
    Update('projects', columns=['name', 'country_code'], filter=by_org),
    Delete('projects', filter=by_org),
    Select(
        'tasks', columns=['id', 'project_id', 'assignee_id', 'title', 'status', 'due_date', 'created_at'], filter=by_org
    ),
    Insert('tasks', columns=['project_id', 'assignee_id', 'title', 'status', 'due_date'], extra=set_org),
    Update('tasks', columns=['assignee_id', 'title', 'status', 'due_date'], filter=by_org),
    Delete('tasks', filter=by_org),
    # table names in statements are written `app.name`, never resolved through the search_path
    default_schema='app',
    qualify_builtins=True,
    max_rows=settings.max_rows,
)
