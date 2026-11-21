# Parental Guidance (p14g)

Check untrusted SQL against an allowlist and rewrite it so it is safe to run on Postgres.

Parental Guidance (p14g) is for running SQL written by someone you do not trust, such as an LLM or an end user,
directly against a Postgres database.
You give it rules for which tables, columns, operators and functions may be used.
It parses each statement with [sqlparser-rs](https://github.com/apache/datafusion-sqlparser-rs), checks it against the
rules, and writes out new SQL for you to run.
It never connects to a database.

It is a Rust library, `p14g`, with a Python package of the same name built with PyO3.

```python
from p14g import Delete, Insert, P14gError, Policy, Select, Update


def add_tenant(context):
    return {'tenant_id': context['tenant_id']}


policy = Policy(
    Select('orders', columns=['id', 'product', 'qty']),
    Insert('orders', columns=['product', 'qty'], extra=add_tenant),
    Update('orders', columns=['qty']),
    Delete('orders'),
)

safe = policy.rewrite('select * from orders where qty < 3')
print(safe.sql)
#> SELECT orders.id, orders.product, orders.qty
#> FROM orders
#> WHERE orders.qty < 3

safe = policy.rewrite("insert into orders (product, qty) values ('tea', 2)", context={'tenant_id': 42})
print(safe.sql)
#> INSERT INTO orders (product, qty, tenant_id)
#> VALUES ('tea', 2, 42)

try:
    policy.rewrite('select * from pg_shadow')
except P14gError as e:
    print(e.kind, e)
    #> denied reading from table "pg_shadow" is not allowed
```

The same policy in Rust:

```rust
use p14g::{Delete, Insert, Policy, Select, Update};

struct Request { tenant_id: i64 }

let policy: Policy<Request> = Policy::builder()
    .select(Select::table("orders").columns(["id", "product", "qty"]))
    .insert(Insert::table("orders").columns(["product", "qty"]).extra(|r: &Request| [("tenant_id", r.tenant_id)]))
    .update(Update::table("orders").columns(["qty"]))
    .delete(Delete::table("orders"))
    .build()?;

let safe = policy.rewrite("select * from orders where qty < 3", &Request { tenant_id: 42 })?;
```

## What you must also do

p14g is one layer of defence.
It does not replace database privileges, and it cannot limit how much work a permitted query does.

- Connect as a role that has been granted only what the policy allows.
  `policy.grants('app_role')` returns the `GRANT` statements for a policy's tables and columns.
  It does not cover sequences that inserted rows take defaults from, or tables a mapper renames statements to.
- Set `statement_timeout` and `lock_timeout` for that role.
  A cross join of two large tables you allowed is a valid query.
- Use a UTF-8 `client_encoding`, or set `literals='params'`.
  Inline string literals are escaped for UTF-8; in an encoding such as SJIS a backslash byte can be the second half of
  a character.
- Set `default_schema`, or write rules as `schema.table`.
  Otherwise table names are written unqualified and Postgres resolves them through the `search_path`, where a
  temporary table or a table in an earlier schema with the same name is found first.
  Functions you add with `functions=[...]` are written as you name them, so give those a schema too.
- Set `qualify_builtins=True` if that `search_path` has a schema that people you do not trust can create functions in.
  Built-in functions are then written `pg_catalog.lower(...)`.
  Postgres looks in `pg_catalog` first, but between functions with different argument types it picks the closest
  match wherever it is in the path, so a `public.lower(varchar)` would be called for a `varchar` argument.
- For rows that must not leak even through error messages or timing, use row-level security or a `security_barrier`
  view as well as, or in place of, a rule's `filter` (see [Rows](#rows)).
- Do not show database error messages to the author of the SQL unless you are content for them to see them.
  A unique-violation error says that a value exists.

## How it works

1. Parse the input with sqlparser. Exactly one statement is accepted.
2. Lower sqlparser's AST into p14g's own representation (`p14g::ast`).
   Only `SELECT`, `INSERT`, `UPDATE` and `DELETE`, and a subset of their syntax, can be represented.
   Everything else is rejected with an `unsupported` error.
3. Bind every column reference to a table in the statement and check it against the rules.
4. Run your mappers, if any.
5. Write the statement out from p14g's representation.

p14g does not print sqlparser's AST back out.
sqlparser 0.64 prints the single literal in `SELECT 'x\'' UNION SELECT password FROM secrets --'` as
`'x\' UNION SELECT password FROM secrets --'`, which Postgres reads as a string, a `UNION` and a comment
(the test `sqlparser_display_is_not_safe_to_emit` shows this).
p14g's writer has no way to emit text it did not escape:

- Identifiers are written in double quotes, with `"` doubled, unless they do not need them (see
  [Output style](#output-style)).
  Names longer than 63 bytes are rejected, because Postgres truncates them.
- String literals are written `'...'` with quotes doubled, or `E'...'` with backslashes doubled when the value contains
  a backslash. Both forms mean the same whether `standard_conforming_strings` is on or off.
- An expression that is an operand of another is parenthesised, and every token is separated by a space.
- Comments are not carried over.

sqlparser is not Postgres's parser, so the two can disagree about what the input means.
That does not matter for safety: what p14g checks is its own representation, and what Postgres runs is text written
from that representation.

## Rules

A statement is rejected unless a rule allows it.

| Rule | Allows |
| --- | --- |
| `Select(table, columns=None, only=False, filter=None)` | Reading the listed columns, or any column without `columns`. |
| `Insert(table, columns=None, extra=None)` | `INSERT ... VALUES` setting the listed columns. |
| `Update(table, columns=None, allow_unfiltered=False, only=False, filter=None)` | `UPDATE ... SET` on the listed columns. |
| `Delete(table, allow_unfiltered=False, only=False, filter=None)` | `DELETE FROM`. |

- `table` is `name` or `schema.name`, spelled as Postgres stores it.
  An unquoted name in the SQL is folded to lower case before it is compared, as Postgres does.
- With `Policy(..., default_schema='public')`, an unqualified name in a rule or a statement means the table in that
  schema, and is written `public.orders`.
  Without it, a rule for `orders` only matches a statement that says `orders`, and the name is written unqualified.
- Every mention of a column is a read and needs a `Select` rule: in a `WHERE`, `ORDER BY` or `JOIN`, in `RETURNING`,
  and on the right of a `SET`.
  A table with an `Insert` rule and no `Select` rule can be inserted into and nothing else.
- Several rules for one table are alternatives.
  Each use of the table must be allowed in full by one of them; their columns are not combined.
- `allow_unfiltered` permits an `UPDATE` or `DELETE` with no `WHERE`.
  Rejecting those catches mistakes. It is not a security control, because `WHERE true` passes.
- `filter` restricts the rows the rule covers (see [Rows](#rows)).
- `only` makes p14g write the table as `ONLY table` (see [Inheritance and partitions](#inheritance-and-partitions)).
  Every `Select`, `Update` and `Delete` rule for one table must agree on it.
- `extra` is a dict, or a callable taking the `context` you pass to `rewrite()` and returning a dict, of columns p14g
  adds to every inserted row.
  A statement that sets one of those columns itself is rejected.

### Columns

p14g has no access to your schema.
A table has the columns its rules list, or an unknown set of columns when a rule allows all of them.

Every column reference is written fully qualified, `table.column`.
If Postgres would have resolved a name differently from p14g, the rewritten query fails in the database.
An unqualified name that could belong to more than one table in the statement is rejected; qualify it.

Whole-row references such as `SELECT orders FROM orders` or `row_to_json(o)` are rejected, because `orders` is not a
column.

`star_behaviour` controls `*`:

- `expand` (default): `*` becomes the columns the rule lists. For a rule that allows all columns it becomes `t.*`.
- `reject`: `*` is an error.
- `allow`: `*` is left as it is, and is an error on a table whose rule lists columns.

### Operators

`Policy(operators=[...])` lists the operators a statement may use.
The default is everything except regular expressions (`~` and `SIMILAR TO`), which a pattern can make very slow.
The list is for the whole statement and cannot be set per table.

### Functions

Functions are matched by name, so every overload of an allowed name is allowed.
`p14g.DEFAULT_FUNCTIONS` (`p14g::functions` in Rust) is allowed unless you pass `default_functions=False`.
`functions=[...]` adds names and `deny_functions=[...]` removes them.

The defaults have no side effects, read nothing but their arguments, and cannot be made to allocate much more than
their input.
That leaves out, among others, `repeat`, `lpad`, `format`, `regexp_*`, `generate_series`, `current_setting`,
`nextval`, `pg_sleep` and everything else named `pg_*`.
`substring` is in the defaults, and `substring(text, text)` is a regular expression match.

Functions are written by name, as `lower(...)`.
With `qualify_builtins=True` the default functions are written `pg_catalog.lower(...)`.

### Rows

A rule's `filter` is a condition every row read or written through the rule has to meet.
It is a function of the `context` you pass to `rewrite()`, and returns an SQL expression and the values for its
`:name` placeholders:

```python
def org(context):
    return 'org = :org_id and deleted_at is null', {'org_id': context['org_id']}


policy = Policy(
    Select('orders', columns=['id', 'qty'], filter=org),
    Insert('orders', columns=['qty'], extra=lambda context: {'org': context['org_id']}),
    Update('orders', columns=['qty'], filter=org),
    Delete('orders', filter=org),
)

print(policy.rewrite('select * from orders where qty > 1', context={'org_id': 42}).sql)
#> SELECT orders.id, orders.qty
#> FROM (SELECT orders.id, orders.qty FROM orders WHERE orders.org = 42 AND orders.deleted_at IS NULL) AS orders
#> WHERE orders.qty > 1

print(policy.rewrite('delete from orders where id = 7 or true', context={'org_id': 42}).sql)
#> DELETE FROM orders
#> WHERE orders.org = 42 AND orders.deleted_at IS NULL AND (orders.id = 7 OR TRUE)
```

- p14g parses the expression itself, so it goes through the same writer as the rest of the statement.
  Each value is written as an escaped literal, or as a parameter with `literals='params'`.
  A value is never read as SQL, whatever it contains.
- A list or tuple is allowed where the placeholder is the only item of an `IN (...)`.
  A cast applies to the bound value: `created > :since::timestamptz`.
- The filter is yours, so it is not checked against the policy.
  It can use columns the statement may not, such as `org` above, and any function or operator.
  It cannot contain a subquery.
- In a `SELECT`, each use of the table becomes a subquery with the filter as its `WHERE`.
  That holds on either side of an outer join, in a self-join and in subqueries, and Postgres flattens it when it plans
  the query.
- In an `UPDATE` or `DELETE`, the filter is added to the `WHERE` with `AND`.
  An `UPDATE` that sets a column the filter uses is rejected, so a row cannot be moved out of it.
- An `INSERT` has no rows to filter. Set the column with `extra`.
- If the filter cannot be used, because a value is missing or the function raises, the statement is rejected.
- A filter with no values can be a plain string: `filter='deleted_at is null'`.
- There can be one `Delete` rule for a table.
  Several `Select` or `Update` rules are still alternatives, each with its own filter, so one rule can allow some
  columns of every row and another all the columns of the user's own rows.

A filter is weaker than Postgres's own row controls in one way.
Postgres may evaluate the statement's conditions on a row before the filter's, so an error such as a division by zero
can reveal something about a row the filter excludes.
p14g's limits on functions and operators narrow that, and do not close it.
Row-level security, or a view declared `WITH (security_barrier = true)`, does:

```sql
CREATE VIEW cheap_orders WITH (security_barrier = true) AS
    SELECT id, product, qty FROM orders WHERE qty < 10
    WITH CHECK OPTION;
GRANT SELECT, INSERT, UPDATE, DELETE ON cheap_orders TO app_role;
```

A view over one table with no aggregates is updatable, and an `UPDATE` or `DELETE` through it only touches rows that
match its `WHERE`.
`WITH CHECK OPTION` rejects an insert or update that would produce a row outside the view.
List the view in the policy like a table.

### Inheritance and partitions

A rule for a table also covers the rows of tables that inherit from it, and of its partitions.
This is how Postgres treats the name: `SELECT`, `UPDATE` and `DELETE` on a parent include the rows of its children,
and privileges are checked on the parent alone, so a role with no grant on a child can still reach its rows this way.
Only the parent's columns are reachable.

If a table has inheritance children the policy should not reach, set `only=True` on its rules.
p14g then writes `ONLY table` wherever a statement reads, updates or deletes it.

```python
policy = Policy(Select('family', columns=['id'], only=True))
print(policy.rewrite('select * from family').sql)
#> SELECT "family".id
#> FROM ONLY "family"
```

Do not set `only` for a partitioned table: the parent holds no rows of its own, so `ONLY` returns nothing.
A statement may also write `ONLY` itself, on any table it is allowed to use.

### Literals and parameters

`rewrite()` returns `SafeSql(sql, params, kind, tables)`.

With `literals='inline'`, the default, string literals are escaped into `sql` and `params` is empty.

With `literals='params'`, each string literal becomes a placeholder and its value is appended to `params`.
Numbers, booleans and `NULL` stay inline.
Placeholders already in the input keep their numbers and p14g's are numbered after the highest of them, so append
`params` to your own parameters.

A parameter has no type until Postgres infers one, which differs from an inline literal in two ways:

- Drivers that send parameters as text (psycopg) behave as inline does.
  Drivers that encode by inferred type (asyncpg) refuse a `str` for a `date` or `integer` parameter.
- Postgres cannot infer a type for an argument of a function that takes any type, such as `concat(a, $1)`, and reports
  `could not determine data type of parameter`. The author has to write `'x'::text`.

### Output style

The output is written from p14g's own representation of the statement, so it does not keep the layout, comments or
spelling of the input.
Two options change how it looks without changing what it means.

`layout='multiline'`, the default, puts each clause of the statement on its own line.
Subqueries stay on one line.
`layout='dense'` writes everything on one line.

`quote_identifiers='minimal'`, the default, quotes a name only when it needs it:

- when it is not made of lower case letters, digits and underscores, or starts with a digit;
- when it is one of the 494 words `pg_get_keywords()` lists on Postgres 18, and does not follow a `.`.
  Unquoted, `user` is the current role and `current_date` is a function call.
  After a `.` Postgres takes any word as a name, so `o.user` needs no quotes.

The name of a function is quoted when it is a keyword, except for `left`, `right` and `replace`: some keywords are
grammar before a `(`, as in `position(a IN b)`.

`quote_identifiers='always'` quotes every name.
Use it if you run a Postgres version newer than p14g has been tested with: a keyword added later is not on the list.

Parentheses are added so that the output never depends on operator precedence, with two exceptions.
An expression that has a clause, a select item or a function argument to itself has none.
A chain of `AND`, or of `OR`, has none around a comparison or test such as `a = 1`, `b IS NULL` or `c IN (...)`: that
relies on `AND` and `OR` binding more loosely than comparisons.

```python
policy = Policy(Select('orders'))
print(policy.rewrite('select id, "user" as "user" from orders where (qty + 1) * 2 > 4 and (a = 1 or b is null)').sql)
#> SELECT orders.id, orders.user AS "user"
#> FROM orders
#> WHERE ((orders.qty + 1) * 2) > 4 AND (orders.a = 1 OR orders.b IS NULL)
```

### Mappers

A mapper replaces a node of a statement that has passed the policy.
It is called with the node and the `context`.

```python
from p14g import Policy, Select, Table, mapper


@mapper(Table)
def per_tenant(table: Table, context):
    return Table(f'{table.name}_{context}', schema='tenants', alias=table.alias)


policy = Policy(Select('events'), mappers=[per_tenant])
print(policy.rewrite('select id from events', context=42).sql)
#> SELECT events.id
#> FROM tenants.events_42 AS events
```

There are mappers for `Table`, `Column`, `Function` and `Literal`.
`COALESCE`, `NULLIF`, `GREATEST`, `LEAST`, `TRIM`, `EXTRACT`, `CURRENT_DATE` and `CURRENT_TIMESTAMP` are grammar in
Postgres, not functions, so a `Function` mapper is not called for them.
They are still allowed and denied by name with `functions` and `deny_functions`.
What a mapper returns is not checked against the policy, so a mapper is trusted code.
It is written by the same writer as the rest of the statement, so it cannot produce unescaped SQL.

## Supported SQL

- `SELECT` with `DISTINCT`, joins with `ON`, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, `LIMIT` and `OFFSET`.
- Subqueries, derived tables with an alias, non-recursive CTEs, `UNION`, `INTERSECT` and `EXCEPT`.
- Comparison, arithmetic and boolean operators, `LIKE`, `ILIKE`, `IN`, `BETWEEN`, `IS`, `CASE`, `CAST` and `::` to a
  fixed list of types, `EXTRACT`, the JSON operators `->`, `->>`, `#>`, `#>>`, `@>` and `<@`.
- Function calls with `DISTINCT`, `ORDER BY`, `FILTER` and `OVER (PARTITION BY ... ORDER BY ...)`.
- `INSERT INTO t (columns) VALUES ...`, `UPDATE t SET ... WHERE ...` and `DELETE FROM t WHERE ...`, each with
  `RETURNING`.

Not supported, and rejected: every other kind of statement, `SELECT INTO`, `FOR UPDATE`, `JOIN ... USING`,
`NATURAL JOIN`, `LATERAL`, table functions, `TABLESAMPLE`, `WITH RECURSIVE`, data-modifying CTEs, `DISTINCT ON`,
`GROUPING SETS`, window frames, arrays and row constructors, `COLLATE`, `AT TIME ZONE`, `ANY`/`ALL`,
`OPERATOR(...)` and custom operators, `table *`, `INSERT ... SELECT`, `ON CONFLICT`, `DEFAULT`, `UPDATE ... FROM` and
`DELETE ... USING`.

`crates/p14g/tests/cases/accept.sql` and `reject.sql` list examples of both, with the SQL each accepted statement
becomes.

## Limits

`Limits` bounds the input before any rule is checked: 64 KiB of SQL, 10,000 tokens, nesting 50 deep, 8 joins,
16 subqueries, 8 set operations, 1,000 items in an `IN` list, 200 select items and 1,000 inserted rows by default.
The select-list limit is checked again once `*` is expanded, since each level of nested subqueries can multiply
the columns of the one below.

sqlparser builds chains such as `1+1+1+...` with a loop, so the parsed tree can be half as deep as the statement has
tokens whatever the nesting limit is.
p14g does not recurse down such a tree beyond the nesting limit, but freeing it is recursive, so the stack is grown
to 1 KiB per token before parsing when the thread has less than that left.

`max_rows` adds a `LIMIT` to a `SELECT` that has none and lowers one that is larger.
Postgres has no `LIMIT` for `UPDATE` or `DELETE`: to cap the rows a write touches, run it in a transaction and check
the row count before committing.

## Development

```bash
make install        # python environment and pre-commit hooks
make test           # rust tests
make postgres       # start Postgres 18 in Docker for the tests below
make test-postgres  # rust tests, including the ones that run p14g's output on Postgres
make python-test    # build the python package and run its tests
make lint           # rustfmt, clippy, ruff, basedpyright, stubtest
make fuzz-mutate    # fuzz with mutations of accepted statements
```

The Postgres tests create a role whose grants match the test policy and run every accepted statement as that role.
A permission error or a syntax error from Postgres fails the test.

The fuzz targets check each statement p14g accepts in two ways.
[libpg_query](https://github.com/pganalyze/libpg_query), Postgres's parser as a library, must parse the output and see
only allowed tables and functions.
When `P14G_TEST_DATABASE_URL` is set, they also run `EXPLAIN` on the output as a role granted `policy.grants()`.
`EXPLAIN` applies Postgres's permission checks without running the statement, so a column the policy should have
refused is reported as a permission error.

### Releasing

CI (`.github/workflows/ci.yml`) runs the pre-commit hooks, the Rust tests against Postgres 18 on stable and the minimum
supported Rust version, the Python tests on every supported Python version, and both fuzz targets.
It builds wheels on every run and tests the built wheel on Linux, macOS and Windows.

Pushing a tag publishes the crate to crates.io and the wheels to PyPI, once those jobs pass.
The tag must match `version` in the root `Cargo.toml`.
The `release` job uses crates.io trusted publishing, so the crate needs a trusted publisher for this
repository with workflow `ci.yml` and environment `release`.
The `release-python` job uses PyPI trusted publishing from an environment called `release-python`.

## License

MIT
