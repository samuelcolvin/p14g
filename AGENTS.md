# AGENTS.md

This file provides guidance to coding agents working with code in this repository.

Don't commit unless the user has just asked you to.

## What this is

p14g takes SQL from an untrusted author, checks it against a `Policy` (allowed tables, columns, operators and
functions), and returns rewritten SQL that is safe to run on Postgres.
It never connects to a database.
`README.md` describes the behaviour users see; read it before changing what is accepted or how output is written.

The workspace has three crates:

- `crates/p14g`: the library, published to crates.io as `p14g`. Use `-p p14g` with cargo.
- `crates/p14g-python`: PyO3 bindings, abi3, published to PyPI as `p14g`. `p14g.pyi` is the hand-written stub.
- `crates/fuzz`: cargo-fuzz targets. It is outside the workspace and has its own `Cargo.lock`.

## The most important restriction: the role cannot change

Nothing p14g accepts may change, reset or get around the role its output runs as, in every dialect, under any policy
whose added functions and filters cannot change it.
The caller's grants and row-level security belong to that role, so a statement that leaves it bypasses everything else.
Treat any way round this as the most serious bug p14g can have, and never add syntax, a default function or a policy
option that weakens it.

What enforces it:

- Only `SELECT`, `INSERT`, `UPDATE` and `DELETE` are lowered (`Lower::statement` in `lower/mod.rs`), and only one
  statement. That leaves out `SET ROLE`, `SET SESSION AUTHORIZATION`, `RESET`, `DISCARD`, every other `SET` (such as
  `search_path` and `row_security`), `GRANT`, `ALTER ROLE`, `DO`, `CALL`, `EXECUTE`, and transaction control:
  `COMMIT`, `ROLLBACK` and `ROLLBACK TO SAVEPOINT` undo a `SET LOCAL ROLE` the caller ran.
- Every `Select` rule lists its columns, and p14g writes only listed names after a table. Postgres's functional notation
  reads `t.name` as the call `name(t)` when `t` has no column `name`, for any function on the `search_path` that takes
  the row, so a rule that allowed every column would let a statement call such functions. Never add a way to allow every
  column.
- Functions are an allowlist only. A default function must not run SQL, change a setting, or be `SECURITY DEFINER`.
  p14g deliberately has no blocklist, since one would read as complete: `DANGEROUS_FUNCTIONS.md` lists some known
  dangerous functions, says it is not exhaustive, and is where a newly found one goes.
- A function a policy adds, or a filter calls, is the policy author's responsibility. `set_config` sets `role`, and the
  built-ins that run SQL given as text (`query_to_xml`, `ts_stat` and others) can call it; the docs on `functions`
  and `filter` warn about them.

What tests it:

- `tests/cases/role.sql` lists the ways in, each with the error kind the test policy gives. `tests/role.rs` checks
  each is rejected, and in every dialect is either rejected or accepted only as a statement that cannot change the role.
- `common::assert_cannot_change_role` checks with libpg_query that output is one of the four statements with no
  call to a function in the test-only `common::ROLE_CHANGING`, no column reference of such a name, and no
  `pg_settings`. `tests/pg_query.rs` calls it on every accepted case.
  It finds calls with `common::called_functions`, which walks the whole tree: pg_query's own `functions()` misses
  calls in `VALUES`, `RETURNING`, `FILTER`, `OVER`, `LIMIT` and elsewhere, so do not use it.
- `run` in `tests/postgres.rs` compares `current_user`, `session_user`, `role`, `search_path`, `row_security`,
  `session_replication_role` and `transaction_read_only` before and after every statement.
  `role_changes_are_caught` checks that comparison does fail. `cases/schema.sql` defines `reset_role(t)` for several
  tables, which an output naming `t.reset_role` would call.
- The fuzzers make the libpg_query check on every output, and with a database check the session's role and settings
  after each `EXPLAIN`. `FRAGMENTS` in `crates/fuzz/src/lib.rs` has role-changing statements and calls.

A new way to change the role goes in `role.sql` and in `FRAGMENTS`.

## Commands

```bash
make install         # python environment (uv) and pre-commit hooks (prek)
make format          # cargo +nightly fmt, ruff format
make lint            # lint-rs and lint-py
make lint-rs         # nightly rustfmt check, clippy -D warnings on the workspace and the fuzz crate, cargo doc
make lint-py         # ruff, basedpyright (strict), mypy.stubtest of p14g.pyi against the built module
make test            # cargo test --workspace; the Postgres tests are skipped
make postgres        # start Postgres 18 in Docker on 127.0.0.1:54329 (container `p14g-test`)
make test-postgres   # cargo test --workspace with P14G_TEST_DATABASE_URL set
make python-test     # maturin develop, then pytest
make fuzz-mutate     # fuzz with mutations of accepted statements; `make fuzz` for raw input
```

A single Rust test: `cargo test -p p14g --test policy quote_identifiers`.
A single Python test: `uv run pytest crates/p14g-python/tests -k test_layout`, after `make python-dev` if the Rust
code changed.

rustfmt needs nightly because `.rustfmt.toml` uses import grouping options.
Clippy runs the pedantic group as errors; silence a lint with `#[expect(..., reason = "...")]`, not `#[allow]`.

To fuzz with the Postgres oracle, which is the only fuzz check that sees columns:

```bash
P14G_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:54329/postgres make fuzz-mutate
```

## Architecture

`Policy::rewrite` in `policy.rs` runs four stages:

1. `lower::parse` tokenises and parses with sqlparser, then lowers sqlparser's AST into p14g's own (`ast.rs`).
2. `check::check` binds every column to a table instance, checks the statement against the rules, and edits the AST
   in place: columns are qualified, `*` is expanded, `extra` insert columns are added, `only` and `default_schema` are
   applied.
3. `check::apply_max_rows` adds or lowers `LIMIT`.
4. `backend::write` writes SQL from the AST.

sqlparser's AST is never written out, and no later stage sees it.
Its `Display` turns one string literal into several tokens for some inputs (`sqlparser_display_is_not_safe_to_emit`).

### The AST (`ast.rs`)

It is small and closed: SQL with no representation is rejected in lowering with an `Unsupported` error.
No node holds raw SQL text. Every string is an `Ident` (validated on construction), a `Literal`, or a fixed enum.

Where Postgres's grammar is narrower than a loose type would be, the type is narrowed and no runtime check is added:
`f(*)` has no `DISTINCT`, `NullIf` has two operands, `KeyExpr` (an `ORDER BY` or `GROUP BY` item) is a position, an
output name or an expression.
If a fix needs the same check in both lowering and the writer, change the type.

### Lowering (`lower/`)

- Destructure every sqlparser struct with all fields named, never `..`, so a sqlparser upgrade that adds a field fails
  to compile. Enums fall through to `Unsupported`.
- `sqlparser` is pinned to an exact version in the root `Cargo.toml` for the same reason.
- Do not call `Spanned::span`, `Display` or `Visit` on an expression, query or statement.
  sqlparser builds operator chains with a loop, so a tree can be half as deep as the input has tokens whatever the
  recursion limit, and those calls overflow the stack. `lower/mod.rs` grows the stack per token before parsing because
  dropping such a tree is also recursive. `deep_input_does_not_overflow` covers this.

### The check (`check.rs`)

p14g has no schema, so the policy is the schema: a table has the columns its rules list.
Scopes, CTEs, derived tables and correlated subqueries are resolved here, and every use of a column is recorded
against a table instance.
A column bound to an enclosing query is written `alias.name`, so a subquery may not hide that alias with one of its
own tables: Postgres would resolve the name to the inner table.
Operators are not: `Policy.operators` is one set for the whole statement, because a set per table would have to follow
each column through every subquery and CTE.
Several rules for one table are alternatives; one rule must cover everything an instance uses.

### Filters (`filter.rs`)

A rule's `filter` is an SQL expression from the policy author with values bound to `:name` placeholders.
`lower::parse_filter` lowers it with the values put in as nodes, so no text is pasted into the output; it is trusted
and not checked against the policy.
The check then puts each filtered table in a `SELECT` behind a subquery (`Checker::filter_tables`), and ANDs the filter
onto the `WHERE` of an `UPDATE` or `DELETE` (`Checker::write_filters`).
A statement whose output has a filtered table does not read back as itself, since the filter would be applied again,
so the shared test policy and the fuzz policies' read-back check leave filtered tables out.

### The writer (`backend/`)

`mod.rs` is the statement writer; `postgres.rs` supplies the pieces behind the `Syntax` trait.

- `expr` writes an operand, in parentheses unless it is a single term. `top` writes an expression that has a clause,
  list item or argument to itself, without them. `chained` handles `AND`/`OR` chains. Use `top` only where the grammar
  takes a whole expression.
- `ident` writes a standalone name and `member` a name after a `.`, where Postgres has no keywords.
  `keywords.rs` is the Postgres 18 keyword list; `tests/postgres.rs` checks it against the server.
- `clause` starts a clause on a new line for the outermost statement in the multiline layout. Write nested queries
  with `subquery` so they stay on one line.

### Python bindings

`Policy<C>` is generic over a context passed to `rewrite` and on to `filter` and `Insert::extra` callbacks; the bindings use
`Py<PyAny>`.
An exception in a Python callback is carried through as a `Callback` error and becomes the `__cause__` of the
`P14gError`.
A change to the Python API needs `p14g.pyi` updated; stubtest fails otherwise.

## Tests

- `tests/cases/accept.sql` and `reject.sql` are the corpus. In `accept.sql` a line starting `=> ` gives the exact output
  for the statement above it; without one the statement only has to be accepted. The test policy for both is
  `tests/common/mod.rs`.
- `tests/cases/schema.sql` creates the database the accepted cases run against, with grants that mirror that policy.
  Change the two together.
- `tests/postgres.rs` is one test function that sets the database up once and calls the checks in turn.
  Every accepted statement is run as the restricted role; a permission or syntax error from Postgres is a p14g bug.
- `tests/pg_query.rs` checks output with libpg_query, Postgres's parser as a library.
- Test policies set `layout='dense'` (`dense()` in `tests/policy.rs`, `DensePolicy` in the Python tests) so expected
  SQL is one line. The defaults are `layout='multiline'` and `quote_identifiers='minimal'`.

New syntax needs changes in `ast.rs`, `lower/`, `check.rs` and `backend/`, a case in each corpus file, and an
entry in `SEEDS` or `FRAGMENTS` in `crates/fuzz/src/lib.rs` so the fuzzer reaches it.

Use the `review-security` skill (`.agents/skills/review-security/SKILL.md`) before merging a change to lowering, the
check, the writer, the default functions or the sqlparser version.
