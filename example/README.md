# p14g example: running untrusted SQL from a FastAPI server

A small multi-tenant app whose users can send their own SQL to `POST /query`.
It uses the three layers the p14g README recommends:

1. **p14g** (`p14g_example/policy.py`) checks each statement against a policy and rewrites it.
   Tables and columns outside the policy are refused, every multi-tenant table is filtered to Anne's org,
   `org_id` is set on inserts, and a `LIMIT 1000` is added.
2. **Grants.** The statement runs as `example_untrusted`, which has only the grants `policy.grants()` returns,
   plus statement, lock and idle timeouts.
3. **Row-level security** on the multi-tenant tables uses the same condition as the p14g filter, reading
   `app.org_id`, which the server sets with `set_config(..., true)` for the transaction.

## Running it

You need Docker, uv and a Rust toolchain: p14g is built from this repository.

```bash
make install   # uv sync
make db        # Postgres 18 in Docker on 127.0.0.1:54331
make setup     # roles, tables, RLS, seed data and grants; prints the grants
make run       # http://127.0.0.1:8014, docs at /docs
make test
```

`make setup` drops and recreates everything, so it can be rerun at any time.

Settings are in `p14g_example/settings.py`, a pydantic-settings model read from environment variables prefixed
`EXAMPLE_` or a `.env` file: `EXAMPLE_ADMIN_DSN`, `EXAMPLE_OWNER_DSN`, `EXAMPLE_UNTRUSTED_DSN`,
`EXAMPLE_OWNER_POOL_SIZE`, `EXAMPLE_UNTRUSTED_POOL_SIZE` and `EXAMPLE_MAX_ROWS`.
The defaults match the database `make db` starts.

```bash
curl -s localhost:8014/query -H 'content-type: application/json' \
  -d '{"sql": "select p.name, count(t.id) from projects p left join tasks t on t.project_id = p.id group by p.name"}'
```

The response holds the rewritten SQL, which is what ran:

```json
{
  "kind": "select",
  "sql": "SELECT p.name, pg_catalog.count(t.id)\nFROM (SELECT projects.id, projects.name, projects.country_code, projects.created_at FROM app.projects WHERE projects.org_id = '10000000-0000-4000-8000-000000000001') AS p\nLEFT JOIN (SELECT tasks.id, ... FROM app.tasks WHERE tasks.org_id = '10000000-0000-4000-8000-000000000001') AS t ON t.project_id = p.id\nGROUP BY p.name\nLIMIT 1000",
  "status": "SELECT 2",
  "columns": ["name", "count"],
  "rows": [["Giant magnet", 1], ["Rocket skates", 2]]
}
```

A refused statement gets a 400 with p14g's error:

```json
{"detail": {"error": "denied", "message": "reading from table \"app.api_keys\" is not allowed", ...}}
```

There is no authentication: anyone can call `/query`, and every statement runs as Anne.
The seed data has two orgs: Acme, with Anne and Bob, and Globex, with Charlie.
Primary keys are UUIDs; the seed rows that `policy.py` and the tests refer to have fixed ones.
Anne sees Acme's data and nothing of Globex's.
The org id is the context `rewrite()` gets, and the filters are functions of it; a real app would take it from the
logged-in user.

## The schema

All tables are in schema `app`, owned by `example_owner`. See `schema.sql`.

| table | untrusted SQL may |
|---|---|
| `countries` | read every row |
| `organisations` | read `id` and `name` of its own org; not `plan` or `stripe_customer_id` |
| `users` | read `id`, `name`, `email`, `created_at` in its own org; not `password_hash` |
| `projects` | read, insert, update and delete in its own org |
| `tasks` | read, insert, update and delete in its own org |
| `api_keys` | nothing |
| `invoices` | nothing, though it is per-org data |
| `audit_log` | nothing; the server writes a row for every request |

`org_id` is not in any rule's columns, so a statement can neither read it nor set it.
The filter adds `org_id = <org>` and the `Insert` rules' `extra` sets it.

## Roles

- `postgres`, the superuser, is used only by `make setup`.
- `example_owner` owns the schema and tables. The server uses it to write the audit log.
  Row-level security does not apply to it, since it owns the tables.
- `example_untrusted` runs p14g's output. It is not a superuser, does not have `BYPASSRLS`, owns nothing, and has
  `statement_timeout = 2s`. `PUBLIC` has no privileges on the database or on schema `public`.

The server keeps a connection pool for each of the two login roles.

## Notes

- Foreign keys are checked without row-level security. A plain `tasks.project_id references projects` would let a
  user attach a task to another org's project. The composite key `(org_id, project_id) references projects (org_id, id)`
  refuses that. The error still tells the user that the id is not in their org, nothing more.
- Database errors are returned as their SQLSTATE only.
  A message such as a unique violation's `Key (email)=(...) already exists` can quote rows outside the org.
- `app.org_id` is set with `set_config('app.org_id', ..., true)`, so it lasts until the end of the transaction and
  does not stay on the pooled connection. p14g does not allow `set_config` in a statement, so users cannot change it.
  Without the setting, row-level security returns no rows.
- `tests/test_example.py` also runs statements as `example_untrusted` directly, without p14g, to check that the grants
  and row-level security hold on their own.
