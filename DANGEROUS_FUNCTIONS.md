# Dangerous functions

**This list is not exhaustive.**
It is some functions known to be dangerous to allow, with the reason for each.
A function that is not here is not thereby safe to add.
Postgres has thousands of functions, extensions add more, and your own schema has its own; nobody has checked them all.

p14g allows only the functions in its default set (`p14g.DEFAULT_FUNCTIONS`, `p14g::functions` in Rust) and the ones
you add with `functions=[...]`.
It has no blocklist: it does not refuse any function you add, or any function a rule's `filter` calls.
Please be extremely careful about adding extra functions unless you know exactly what they do.
A function is matched by name, so adding a name allows every overload of it.

Before adding a function, check that it:

- has no side effects, and does not change a setting;
- does not run SQL given to it as text, and does not read a table or file named by an argument;
- is not `SECURITY DEFINER`, and calls nothing that does any of the above;
- cannot be made to use far more time or memory than the size of its arguments.

## Change the role or a setting

The role a statement runs as is what its grants and row-level security belong to, so these get round everything else.

| Function | Why |
| --- | --- |
| `set_config` | Sets any setting the session can: `role` (`'none'` resets it to the session user), `search_path`, `row_security`, and the custom settings row-level security policies read, such as `app.org_id`. |
| `UPDATE pg_settings` | Not a function, but `pg_settings` has an `UPDATE` rule that calls `set_config`, so an `Update` rule for it is the same. |

## Run SQL given as text

Each of these runs a query written in a string, which p14g sees only as a literal.
That query can call `set_config`, read any table the role can, or do anything else the role can do.

| Function | Why |
| --- | --- |
| `query_to_xml`, `query_to_xml_and_xmlschema` | Run the query and return its rows as XML. |
| `query_to_xmlschema` | Plans the query, without running it, and returns the XML schema of its result. Planning still reads the catalog for every table the query names. |
| `ts_stat` | Runs the query to collect statistics on its `tsvector` column. |
| `ts_rewrite` | The two-argument form runs a query that returns the rewrite rules. |
| `dblink`, `dblink_exec`, `dblink_open`, `dblink_send_query` and the other `dblink_*` functions (extension `dblink`) | Connect to a database, possibly this one and as another user, and run SQL there. |
| `crosstab` (extension `tablefunc`) | Runs the source and category queries. |
| `connectby` (extension `tablefunc`) | Builds a query from the table and column names it is given. |
| `pgr_*` (extension `pgrouting`) | Nearly every routing function takes the SQL for its edges as text. |
| `pg_background_launch` and the other `pg_background_*` functions (extension `pg_background`) | Run SQL in a background worker, which carries on after the statement. |
| `cron.schedule`, `cron.schedule_in_database`, `cron.alter_job` (extension `pg_cron`) | Run SQL later, on a schedule. |
| pgTAP's test functions, such as `results_eq` and `throws_ok` | Run the queries they compare. |

## Read tables named by an argument

These read a table, schema or database named in an argument, so p14g's table and column rules and filters do not apply.
The role's grants and row-level security still do.

| Function | Why |
| --- | --- |
| `table_to_xml`, `table_to_xmlschema`, `table_to_xml_and_xmlschema` | Read every column of the named table. |
| `schema_to_xml`, `schema_to_xmlschema`, `schema_to_xml_and_xmlschema` | Read every table in the schema. |
| `database_to_xml`, `database_to_xmlschema`, `database_to_xml_and_xmlschema` | Read every table in the database. |
| `cursor_to_xml`, `cursor_to_xmlschema` | Read from a cursor by name. |

## Files and the server

Most of these need superuser or a role such as `pg_read_server_files`, but should never be allowed whatever the role.

| Function | Why |
| --- | --- |
| `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file` and the other `pg_ls_*` functions | Read files and directories on the database server. |
| `lo_import`, `lo_export` | Copy a file on the server into a large object, or a large object out to a file. |
| `lo_create`, `lo_from_bytea`, `lo_put`, `lo_unlink` and the other `lo_*` functions | Create, change and delete large objects, which live outside any table a policy names. |
| `pg_reload_conf`, `pg_rotate_logfile`, `pg_switch_wal`, `pg_create_restore_point` | Act on the server. |

## Other sessions and shared state

These reach past the statement: to other sessions, to the next user of a pooled connection, or to state a rollback does
not undo.

| Function | Why |
| --- | --- |
| `pg_terminate_backend`, `pg_cancel_backend` | End or cancel another session's query. A role can do this to every session of the same role, which is everyone if all users share one. |
| `pg_advisory_lock` and the other `pg_advisory_*` and `pg_try_advisory_*` functions | A session-level lock outlives the transaction and stays on a pooled connection; any lock can block other sessions. |
| `pg_notify` | Sends a message to every session listening on the channel, which may act on it. |
| `nextval`, `setval` | Change a sequence, which a rollback does not undo. |
| `setseed` | Sets the seed `random()` uses for the rest of the session. |

## Unbounded work

A statement timeout stops these, but a single call can use a great deal of memory before it does.

| Function | Why |
| --- | --- |
| `repeat`, `lpad`, `rpad`, `format` | A length or width from the query lets one call allocate gigabytes. |
| `regexp_*`, `substring(text, text)` | A regular expression can be made very slow. `substring` is a default, and its two-text form is a regular expression match. |
| `generate_series`, `unnest`, `jsonb_array_elements`, `regexp_split_to_table` | Return many rows from one call. |
| `pg_sleep`, `pg_sleep_for`, `pg_sleep_until` | Hold a connection for as long as they are asked to. |

## Server and session information

These do no harm themselves but tell the SQL author about the server.

| Function | Why |
| --- | --- |
| `version`, `inet_server_addr`, `inet_server_port`, `pg_postmaster_start_time` | The server's version, address and uptime. |
| `current_setting` | Any setting the role can see, including custom settings, which sometimes hold secrets. |
| `current_user`, `session_user`, `current_database`, `pg_backend_pid` | Who and where the session is. |
| `has_table_privilege` and the other `has_*_privilege` functions, `to_regclass`, `pg_get_*def`, `pg_relation_size` | Read the catalog, so the author can find out what exists. |

## Your own functions

p14g cannot see inside a function, so check every one you add, and every one a filter calls:

- A `SECURITY DEFINER` function runs with its owner's privileges, whatever role calls it.
- A function that calls `set_config`, or runs SQL with `EXECUTE` in PL/pgSQL, can change the role.
  One that builds that SQL from its arguments can also be injected into.
- A function that writes to a table does so whatever the policy says about that table.
- Postgres gives `PUBLIC` `EXECUTE` on every new function.
  Revoke it, and grant it back only where it is needed, so that a function you did not add cannot be called even if
  something gets past p14g.
