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

- `set_config` sets any setting the session can: `role` (`'none'` resets it to the session user), `search_path`,
  `row_security`, and the custom settings row-level security policies read, such as `app.org_id`.
- `UPDATE pg_settings` is not a function, but `pg_settings` has an `UPDATE` rule that calls `set_config`, so an
  `Update` rule for it is the same.

## Run SQL given as text

Each of these runs a query written in a string, which p14g sees only as a literal.
That query can call `set_config`, read any table the role can, or do anything else the role can do.

- `query_to_xml` and `query_to_xml_and_xmlschema` run the query and return its rows as XML.
- `ts_stat` runs the query to collect statistics on its `tsvector` column.
- `ts_rewrite`, in its two-argument form, runs a query that returns the rewrite rules.
- `dblink`, `dblink_exec`, `dblink_open`, `dblink_send_query` and the other `dblink_*` functions (extension `dblink`)
  connect to a database, possibly this one and as another user, and run SQL there.
- `crosstab` (extension `tablefunc`) runs the source and category queries.
- `connectby` (extension `tablefunc`) builds a query from the table and column names it is given.
- `pgr_*` (extension `pgrouting`): nearly every routing function takes the SQL for its edges as text.
- `pg_background_launch` and the other `pg_background_*` functions (extension `pg_background`) run SQL in a background
  worker, which carries on after the statement.
- `cron.schedule`, `cron.schedule_in_database` and `cron.alter_job` (extension `pg_cron`) run SQL later, on a schedule.
- pgTAP's test functions, such as `results_eq` and `throws_ok`, run the queries they compare.

## Read tables named by an argument

These read a table, schema or database named in an argument, so p14g's table and column rules and filters do not apply.
The role's grants and row-level security still do.

- `table_to_xml`, `table_to_xmlschema` and `table_to_xml_and_xmlschema` read every column of the named table.
- `schema_to_xml`, `schema_to_xmlschema` and `schema_to_xml_and_xmlschema` read every table in the schema.
- `database_to_xml`, `database_to_xmlschema` and `database_to_xml_and_xmlschema` read every table in the database.
- `cursor_to_xml` and `cursor_to_xmlschema` read from a cursor by name.
- `query_to_xmlschema` plans the query given as text, without running it.

## Files and the server

Most of these need superuser or a role such as `pg_read_server_files`, but should never be allowed whatever the role.

- `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file` and the other `pg_ls_*` functions read files and
  directories on the database server.
- `lo_import` and `lo_export` copy a file on the server into a large object, or a large object out to a file.
- `lo_create`, `lo_from_bytea`, `lo_put`, `lo_unlink` and the other `lo_*` functions create, change and delete large
  objects, which live outside any table a policy names.
- `pg_reload_conf`, `pg_rotate_logfile`, `pg_switch_wal` and `pg_create_restore_point` act on the server.

## Other sessions and shared state

These reach past the statement: to other sessions, to the next user of a pooled connection, or to state a rollback does
not undo.

- `pg_terminate_backend` and `pg_cancel_backend` end or cancel another session's query.
  A role can do this to every session of the same role, which is everyone if all users share one.
- `pg_advisory_lock` and the other `pg_advisory_*` and `pg_try_advisory_*` functions take locks. A session-level lock
  outlives the transaction and stays on a pooled connection, and any lock can block other sessions.
- `pg_notify` sends a message to every session listening on the channel, which may act on it.
- `nextval` and `setval` change a sequence, which a rollback does not undo.
- `setseed` sets the seed `random()` uses for the rest of the session.

## Unbounded work

A statement timeout stops these, but a single call can use a great deal of memory before it does.

- `repeat`, `lpad`, `rpad` and `format` take a length or width from the query, so one call can allocate gigabytes.
- `replace` can return the string's length times the replacement's, and nested calls multiply: three calls in 5 KB of
  SQL build a 1 GB string in about a second. `work_mem` and `temp_file_limit` do not limit it.
- `regexp_*` and `substring(text, text)` match a regular expression, which can be made very slow.
  `substring` is a default, and its two-text form is a regular expression match.
- `generate_series`, `unnest`, `jsonb_array_elements` and `regexp_split_to_table` return many rows from one call.
- `pg_sleep`, `pg_sleep_for` and `pg_sleep_until` hold a connection for as long as they are asked to.

## Server and session information

These do no harm themselves but tell the SQL author about the server.

- `version`, `inet_server_addr`, `inet_server_port` and `pg_postmaster_start_time` give the server's version, address
  and uptime.
- `current_setting` returns any setting the role can see, including custom settings, which sometimes hold secrets.
- `current_user`, `session_user`, `current_database` and `pg_backend_pid` say who and where the session is.
- `has_table_privilege` and the other `has_*_privilege` functions, `to_regclass`, `pg_get_*def` and `pg_relation_size`
  read the catalog, so the author can find out what exists.

## Your own functions

p14g cannot see inside a function, so check every one you add, and every one a filter calls:

- A `SECURITY DEFINER` function runs with its owner's privileges, whatever role calls it.
- A function that calls `set_config`, or runs SQL with `EXECUTE` in PL/pgSQL, can change the role.
  One that builds that SQL from its arguments can also be injected into.
- A function that writes to a table does so whatever the policy says about that table.
- Postgres gives `PUBLIC` `EXECUTE` on every new function.
  Revoke it, and grant it back only where it is needed, so that a function you did not add cannot be called even if
  something gets past p14g.
