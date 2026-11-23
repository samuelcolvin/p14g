# Threat model

p14g takes one SQL statement from someone you do not trust, checks it against a `Policy`, and returns SQL that you run
on Postgres as a restricted role.
This file says who p14g trusts and who it defends against, what p14g guarantees, what you have to do for those
guarantees to hold, and what counts as a vulnerability.

## Untrusted: the SQL author

The SQL passed to `rewrite()` is the only untrusted input.
Assume whoever wrote it is hostile, adapts to what they see, and can send as many statements as they like.
An LLM is in this position whatever its instructions say, because anything it read, such as a web page or a document,
can steer what it writes.
Assume the author learns whether each statement succeeded, the rows it returned, and, unless you hide them, Postgres's
error messages.

## Trusted: everything else

- The policy author, and everything in the policy: rules, filters, `Insert.extra` callbacks, added functions.
  p14g does not check what a filter or an `extra` produces against the policy.
- The `context` you pass to `rewrite()`.
  It usually says who the request is for, and p14g believes it.
  Values from it can still contain anything: a value bound to a filter placeholder or returned by `extra` is written as
  an escaped literal or a parameter, never as SQL.
- The code that calls p14g and runs its output, the Postgres server and its configuration, and the owner of the tables.
- sqlparser and the Rust and Python toolchains.
  p14g does not rely on sqlparser reading the input the way Postgres would, since the output is written from p14g's own
  AST, but a bug in sqlparser that crashes or hangs on hostile input is a p14g vulnerability.

## What you must do

The guarantees below hold only in a deployment that does all of this.
The README's [Security considerations](README.md#security-considerations) has the detail.

- Run the output as a role that has only the grants `policy.grants()` returns, plus `USAGE` on the sequences that
  inserted rows take defaults from.
  Never run it as the owner of the tables, a superuser, or a role with `BYPASSRLS`.
- Set a time limit on every query: `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` on
  that role.
  p14g bounds the size of a statement, not how long it runs.
- Limit the memory and temporary disk a query can use: `work_mem` and `temp_file_limit` on that role, and
  `max_parallel_workers_per_gather = 0`.
- Where rows belong to different users, put row-level security on the table and give the rule a `filter` with the same
  condition.
  Set the setting the row-level security policy reads with `SET LOCAL` or `set_config(..., true)` in the transaction
  that runs the statement.
- Set `default_schema` or write rules as `schema.table`, and make sure nobody you do not trust can create objects in a
  schema on the role's `search_path`: functions, operators and types are written by name and looked up through it.
  `search_path = ''` on the role does both.
- Create views over tables with row-level security `WITH (security_invoker = true)`, or the view reads them as its
  owner and the row-level security does not apply.
- Use a UTF-8 `client_encoding`, or `literals='params'`.
- Show Postgres's error messages to the SQL author only if you are content for them to read what the messages say.
- Use a current 18.x minor release of Postgres, the version p14g's keyword list and tests are for.
  A later version can add keywords, which p14g would write as bare names.

## What p14g guarantees

For any statement `rewrite()` accepts, in a deployment that does the above:

- It cannot change, reset or get around the role it runs as, under any policy whose added functions and filters
  cannot change it.
  This is the guarantee the rest depend on, since the grants and row-level security belong to that role.
  `SET ROLE`, `SET SESSION AUTHORIZATION`, `RESET`, `DISCARD`, every other `SET`, and `COMMIT`, `ROLLBACK` and
  `ROLLBACK TO SAVEPOINT`, which undo a `SET LOCAL ROLE`, are all statements other than the four below.
  No default function can change it.
  p14g writes after a table only column names that table's `Select` rule lists.
  Postgres's functional notation reads `t.name` as the call `name(t)` when `t` has no column `name`, for any function
  on the `search_path` that takes the row, and no spelling avoids it: quoting, `(t).name` and `(t.*).name` all call it.
  A subquery may not give one of its tables the alias of a table in an enclosing query whose column it uses, since
  Postgres would resolve `alias.name` to the inner table.
  p14g does not refuse any function a policy adds or a filter calls, or an `UPDATE` rule for `pg_settings`.
  `set_config`, the built-ins that run SQL given as text such as `query_to_xml`, and updates of `pg_settings` can all
  change it; [DANGEROUS_FUNCTIONS.md](DANGEROUS_FUNCTIONS.md) has more, and is not exhaustive.
- The output is one `SELECT`, `INSERT`, `UPDATE` or `DELETE`, and Postgres parses it as the statement p14g checked.
  No text from the input reaches the output: names are validated and quoted, literals are escaped, and everything else
  is written from a fixed set of tokens.
- It reads only tables and columns a `Select` rule allows, with one rule covering every column used on each table.
  Whole-row references such as `row_to_json(t)` are refused.
  Every `Select` rule lists its columns; system columns such as `ctid` and `xmin` are refused unless one lists them.
- It writes only the columns an `Insert` or `Update` rule lists, plus the columns `extra` sets.
- It calls only the functions the policy allows and uses only the operators it allows, and casts only to p14g's fixed
  list of types.
- A rule's `filter` is applied to every use of its table: each `FROM` item at every level of the statement, and the
  target of an `UPDATE` or `DELETE`.
  If the filter cannot be applied, the statement is refused.
- A `SELECT` has a `LIMIT` no larger than `max_rows`, if the policy sets one.

For any input at all, `rewrite()` returns a result or a `P14gError` within the bounds of `Limits`.
It does not panic, overflow the stack, or use time or memory out of proportion to the input.

### Rows

A filter together with row-level security on the same condition is a boundary between users' rows: the SQL author can
neither read rows outside it nor learn that they exist.

A filter without row-level security guarantees only which rows a statement returns, updates and deletes.
The statement can still learn about rows the filter excludes.
Postgres flattens the subquery p14g writes for a filter, then evaluates the conditions on the table in order of
estimated cost, so a condition in the statement that is cheaper than the filter runs first, on every row.
A condition such as `1 / (id - 3) > 0` then fails or succeeds depending on whether some other user has a row with
`id = 3`.
Row-level security evaluates its condition before any condition in the statement that is not `LEAKPROOF`, which closes
this.
The README's [Rows](README.md#rows) section has more on filters.

## What p14g does not protect against

- Load on the database from statements it accepts.
  A cross join of two allowed tables is a valid statement; the time limits above are what stop it.
- What Postgres's error messages say.
  A unique-violation or foreign key error reveals that a value exists, with or without row-level security, because
  Postgres checks constraints without it.
- Timing.
  How long a statement takes can depend on rows the author cannot read.
- Mistakes in the policy: a column or table allowed that should not be, an added function with side effects, an
  `Insert` on a filtered table with no `extra` for the filter's column.
  An added function, or one a filter calls, that is `SECURITY DEFINER` runs as its owner, and one that calls
  `set_config` or runs SQL can change the role; [DANGEROUS_FUNCTIONS.md](DANGEROUS_FUNCTIONS.md) has some known
  examples, and is not exhaustive.
  A name a `Select` rule lists that is not a column of the table is read by Postgres, through functional notation, as
  a call to a function of that name; running `policy.grants()` catches it, since a column grant fails on a column that does not exist.
- Sequences that inserted rows take defaults from, which the grants do not cover.
  The grants also cannot express a filter, so they let the role read and write every row.
- A compromised database, application, or Python process.

## What counts as a vulnerability

A vulnerability is something the SQL author can do.
Something only a policy author could cause is a documentation or usability issue, unless the policy looks safe and is
not.

These are vulnerabilities:

- Output that changes the role, the session user, or a setting such as `search_path` or `row_security`, under any
  policy that does not add or call in a filter a function that does so.
- Output that runs and does something the policy does not allow: reads a table or column no rule allows,
  writes a column no rule lists, calls a function the policy does not allow, or uses a table without its filter.
- With a filter and row-level security on the same condition, a way to read or learn about rows both exclude.
- Output that Postgres parses differently from the statement p14g checked, whether or not it runs.
- Output that fails with a permission error (`42501`) when run as a role with exactly the grants above.
  The grants allow more than the policy does, since they combine the columns of every rule for a table, so a
  permission error means p14g accepted something outside the policy and only the grants stopped it.
- Output that fails with a syntax error (`42601`), unless the error is about meaning rather than syntax, such as each
  side of a `UNION` having a different number of columns.
  A syntax error means Postgres read the output differently from p14g, which is how injection starts.
- A panic, stack overflow, hang, or memory use out of proportion to the input in `rewrite()`, including in sqlparser.
- In the Python package, an exception in a callback that does not reject the statement, or a way to build an AST that
  skips validation of names or numbers.

These are bugs, to report as ordinary issues:

- Output that names a table that does not exist (`42P01`).
- A Postgres error about meaning that p14g could have caught without a schema, such as a `UNION` with a different number
  of columns on each side.
- A statement refused that is safe and that the policy allows.

These are not failures:

- Postgres refusing output for a reason p14g cannot know without the schema: a type mismatch, an aggregate in
  `WHERE`, the wrong number of arguments to a function.
- Errors from the data: division by zero, a failed cast, a constraint violation.
- A statement that is slow.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting, at
<https://github.com/samuelcolvin/p14g/security/advisories/new>.
Do not open a public issue.
Include the policy, the input SQL, the output, and what the output did when you ran it, if you did.

## How the guarantees are tested

- `tests/cases/accept.sql` and `reject.sql` give statements that must be accepted, with their exact output, and
  statements that must be refused.
  `tests/cases/role.sql` lists the ways to change or reset the role, and `tests/role.rs` checks each is refused in
  every dialect.
- `tests/postgres.rs` runs every accepted statement against Postgres 18 as a role whose grants match the test policy.
  A permission or syntax error fails the test, and so does a change to the role or to `search_path`, `row_security`
  or `session_replication_role`.
  The test schema has a function `reset_role(t)` for several tables, which an output naming `t.reset_role` would call
  through functional notation.
  It also checks the keyword list against the server and that filters hold through joins, subqueries and writes.
- `tests/pg_query.rs` parses the output with libpg_query, Postgres's own parser, and checks it is one `SELECT`,
  `INSERT`, `UPDATE` or `DELETE` with no call to a function that can change the role.
- The fuzzers in `crates/fuzz` run hostile and mutated input through `rewrite()` and check that the output reads back
  as itself.
  They check every output is one `SELECT`, `INSERT`, `UPDATE` or `DELETE` with no call to such a function, and splice in
  statements and calls that change the role.
  With `P14G_TEST_DATABASE_URL` set they also run each output through `EXPLAIN`, fail on a permission, syntax or
  undefined-table error, and check the session is still the restricted role afterwards.
