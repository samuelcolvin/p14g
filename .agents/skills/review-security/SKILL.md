---
name: review-security
description: Security review of the current branch against its merge base — SQL injection through the writer, syntax accepted without being understood, policy bypasses, and crashes or unbounded work on hostile input. Use when reviewing changes for security risk, or before merging anything touching lower/, check.rs, backend/, functions.rs or a sqlparser upgrade.
---

# Security review

pgsafe takes SQL from an untrusted, potentially malicious author and returns SQL that the caller runs on their
database. Review this branch on that basis.

```bash
git diff origin/main...HEAD   # or main...HEAD when there is no remote
```

If the branch has a PR, read its review threads (`gh pr view --comments`) for security findings already raised, and
confirm each is properly addressed.

Cover the changes **and any code they touch**: a caller made unsafe by a changed callee is in scope even if it isn't in
the diff.

The policy author, mappers and `Insert.extra` callbacks are trusted. The SQL passed to `check()` is not.
A finding is something the SQL author can do; note misuse a policy author could plausibly fall into separately.

## The writer (`backend/`)

The output is only as safe as the text the writer produces. Ask:

- **Can any byte reach the output without being escaped or validated?**
    Every string in the IR is an `Ident`, a `Literal`, or chosen from a fixed table.
    A new IR node or field holding free text, or a `push`/`format!` of a value that came from the input, is a finding.
- **Are the three escapers still right?**
    `Syntax::ident` (double `"`), `Syntax::string` (double `'`, `E'...'` with doubled backslashes when the value has
    one) and `valid_number`. A string must read the same with `standard_conforming_strings` on and off. `Ident::new` must
    still reject NUL, empty names and names over 63 bytes.
- **Can two tokens run together or change precedence?**
    Nested expressions are parenthesised and tokens are separated by spaces. Look for a new construct written without
    either (`- -1` becoming a comment, `a OR b AND c` regrouping).
- **Is anything written unqualified that Postgres could resolve to something else?**
    Columns are written `"table"."column"`, default functions `pg_catalog.name`, and tables with their schema when the
    rule or `default_schema` gives one. The bare forms that exist (insert columns, `SET` targets, `OutputColumn`,
    `Ordinal`) each need a reason they cannot name something unchecked.
- **Does any path call `Display`/`to_string()` on a sqlparser node for output?**
    Its escaping is unsafe (`sqlparser_display_is_not_safe_to_emit`). Error messages are the only allowed use.

## Lowering (`lower/`)

Syntax that is accepted without being represented is syntax that is silently dropped or misread. Ask:

- **Is every sqlparser struct still destructured with all fields named?**
    A `..` in a pattern, or a field bound to `_` without a comment saying why it cannot matter, hides new syntax.
- **Does every enum fall through to `Unsupported`?**
    A wildcard arm that accepts, or a variant mapped to a nearby meaning it does not have, is a finding.
- **Does the lowered IR mean what Postgres will make of the output?**
    sqlparser is not Postgres's parser. That is safe only while the output is written from the IR, so check rewrites
    such as `TRIM` → `btrim`, `POSITION(a IN b)` → `position(b, a)` and typed literals → `CAST` against Postgres itself.
- **sqlparser upgrade?**
    Read its changelog for new fields, variants and dialect behaviour, and confirm the build broke where it should have.

## The policy check (`check.rs`, `policy.rs`)

Ask what the SQL author can now read, write or call that no rule names:

- **Is every column reference resolved, recorded and qualified?**
    A new `Expr` variant or clause that is not walked by `expr()` is a column the policy never sees. This includes
    `ORDER BY`, `GROUP BY`, `HAVING`, join conditions, `RETURNING`, the right side of `SET`, window and aggregate
    clauses.
- **Can a name resolve to a different table than Postgres will pick?**
    Scopes, CTE shadowing, derived tables, correlated subqueries, aliases, unqualified names beside an all-columns
    table. A wrong binding must fail in the database, not read another column.
- **Are rules still alternatives?**
    One rule must cover all the columns and operators used on a table instance; combining two rules is a bypass.
- **Whole rows and system columns?**
    `SELECT t FROM t`, `t.*` in an expression, `row_to_json(t)`, `ctid`, `xmin`, `tableoid` must stay unreachable
    unless a rule lists them.
- **Star handling?**
    `allow` must refuse a table whose rule lists columns; `expand` must use the columns of the rule that was chosen.
- **Writes?**
    Insert columns, `SET` targets, `extra` collisions, the unfiltered guard, and that anything a write reads needs a
    `Select` rule. `only` and `default_schema` must be applied to every reference to the table, including write
    targets.
- **Functions, operators and cast types?**
    Each addition to `functions.rs` defaults, the `Op`/`BinaryOperator` sets or `DataType` is a grant to every policy.
    A default function must have no side effects, read only its arguments, and not turn a small input into a large
    allocation or a regular expression match. Check every overload of the name, since matching is by name.

## Crashes and unbounded work

`check()` runs inside the caller's server on input chosen by an attacker. Ask:

- **Recursion over a sqlparser tree?**
    sqlparser builds operator chains with a loop, so a tree can be half as deep as the statement has tokens, whatever
    the recursion limit. `Spanned::span`, `Display`, `Visit` and any new recursive helper must not be called on
    expressions, queries or statements. Only names and literals are flat. `deep_input_does_not_overflow` must cover a
    new kind of chain.
- **Is each new construct counted against a limit before work is done on it?**
    Token count, depth, nodes, joins, subqueries, set operations, `IN` lists, select items, `VALUES` rows.
- **Anything quadratic in the input?**
    A `contains` or nested loop over a list whose length the SQL author controls.
- **Panics?**
    `unwrap`, `expect`, indexing or slicing reachable from the input, integer overflow feeding a length or a
    placeholder number. In the Python package a panic becomes a `PanicException` that callers will not be catching.

## The Python bindings (`crates/pgsafe-python`)

- **Can Python construct IR that skips validation?**
    Names must go through `Ident::new`; numbers must reach the writer as text that `valid_number` checks.
- **Do callbacks fail closed?**
    An exception or a wrong return type in a mapper or `extra` must reject the statement, with the original exception
    as `__cause__`.
- **Is `context` only ever passed through?**
    It must not be read, stored on the policy, or shared between calls.

## Evidence

A claim that something is safe needs a test that would fail if it were not:

- A statement in `tests/cases/accept.sql` or `reject.sql` for each new piece of syntax, allowed and refused.
- `make test-postgres`: every accepted statement runs as a role whose grants mirror the test policy, so a permission
    or syntax error from Postgres is a pgsafe bug. Extend `schema.sql` when the change needs a new kind of object.
- `make fuzz-mutate` for a few minutes after any change to lowering, the check or the writer. Add new syntax to
    `SEEDS` or `FRAGMENTS` in `crates/fuzz/src/lib.rs` so the fuzzer reaches it.

## Report

Per finding: the attack, `file:line`, the SQL (and policy) that triggers it, the SQL pgsafe emits, and the impact.
Demonstrate with a test or a run against Postgres rather than asserting where you can. Say which areas you checked and
found clean; coverage matters as much as findings.

Report only, unless the user asks for fixes.
