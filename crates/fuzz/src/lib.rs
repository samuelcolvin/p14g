//! The properties both fuzz targets check.
//!
//! Whatever the input, `Policy::check` must not panic. When it accepts a statement, Postgres's own parser
//! must agree with pgsafe about what the output is: it parses as one statement, it only touches tables
//! and functions the policy allows, and pgsafe reading its own output back gets the same SQL again.

use std::{collections::BTreeSet, sync::LazyLock};

use pgsafe::{Delete, ErrorKind, Insert, Literals, Op, Policy, PolicyBuilder, Select, Update, functions};

/// The same shape of policy as the test suite: column lists, an all-columns view, a schema-qualified
/// table, a rule with few operators, and writes.
fn builder() -> PolicyBuilder {
    Policy::builder()
        .select(Select::table("orders").columns(["id", "product", "qty", "customer_id"]))
        .select(Select::table("customers").columns(["id", "name"]))
        .select(Select::table("v"))
        .select(Select::table("app.events").columns(["id", "kind"]))
        .select(
            Select::table("limited")
                .columns(["a", "b"])
                .operators([Op::Eq, Op::And]),
        )
        .insert(Insert::table("orders").columns(["product", "qty"]))
        .insert(Insert::table("audit").columns(["message"]))
        .update(Update::table("orders").columns(["qty"]))
        .delete(Delete::table("orders"))
}

const TABLES: &[&str] = &["orders", "customers", "v", "app.events", "limited", "audit"];

static INLINE: LazyLock<Policy> = LazyLock::new(|| builder().build().unwrap());
static PARAMS: LazyLock<Policy> = LazyLock::new(|| builder().literals(Literals::Params).build().unwrap());

/// Run every check on one input.
pub fn check(sql: &str) {
    for policy in [&*INLINE, &*PARAMS] {
        let Ok(safe) = policy.check(sql, &()) else {
            continue;
        };
        let parsed = pg_query::parse(&safe.sql).unwrap_or_else(|e| {
            panic!(
                "Postgres cannot parse the output\n input: {sql}\noutput: {}\n error: {e}",
                safe.sql
            )
        });
        assert_eq!(
            parsed.protobuf.stmts.len(),
            1,
            "more than one statement\n input: {sql}\noutput: {}",
            safe.sql
        );

        let cte_names: BTreeSet<&String> = parsed.cte_names.iter().collect();
        for table in parsed.tables() {
            assert!(
                TABLES.contains(&table.as_str()) || cte_names.contains(&table),
                "Postgres sees table {table:?}\n input: {sql}\noutput: {}",
                safe.sql
            );
            assert!(
                safe.tables.contains(&table) || cte_names.contains(&table),
                "table {table:?} is not in the reported tables {:?}\n input: {sql}\noutput: {}",
                safe.tables,
                safe.sql
            );
        }
        for function in parsed.functions() {
            let allowed = function
                .strip_prefix("pg_catalog.")
                .is_some_and(|name| functions::is_default(name) || name == "btrim" || name == "like_escape");
            assert!(
                allowed,
                "Postgres sees function {function:?}\n input: {sql}\noutput: {}",
                safe.sql
            );
        }

        match policy.check(&safe.sql, &()) {
            Ok(again) => {
                // in params mode the literals are already placeholders, so there is nothing new to bind
                assert_eq!(again.sql, safe.sql, "not idempotent\n input: {sql}");
            }
            // expanding `*` can push the output over a limit the input was under
            Err(e) if e.kind() == ErrorKind::Limit => {}
            Err(e) => panic!("the output was rejected: {e}\n input: {sql}\noutput: {}", safe.sql),
        }
    }
}

/// Statements the policy accepts, to mutate.
pub const SEEDS: &[&str] = &[
    "select id from orders where qty < 3",
    "select * from orders",
    "select o.*, c.name from orders o join customers c on c.id = o.customer_id where c.name like 'a%' order by o.id desc limit 10",
    "select name, count(*) as n from orders join customers on customers.id = customer_id group by name having count(*) > 1 order by n desc",
    "select v.id, lower(v.product) lp from v where qty is not null",
    "select 'it''s', $$dollar$$, E'esc\\'q', 'back\\slash' from orders",
    "select id from orders where id in (select customer_id from orders where qty between 1 and 5) and not exists (select 1 from customers where customers.id = orders.customer_id)",
    "with big as (select id, qty from orders where qty > 10) select big.id from big join orders on orders.id = big.id",
    "select id from orders union all select id from customers order by id limit 5",
    "select x.id from (select id from orders) x",
    "select case when qty > 1 then 'many' else 'one' end as label from orders group by label",
    "select cast(qty as text), qty::bigint, date '2020-01-01', interval '1 day' from orders",
    "select count(distinct product), sum(qty) filter (where qty > 0) from orders",
    "select row_number() over (partition by customer_id order by id) from orders",
    "select coalesce(qty, 0), trim(both 'x' from product), extract(year from now()), substring(product from 1 for 2), position('a' in product) from orders",
    "select a from limited where a = 1 and b = 2",
    "select id from app.events",
    "insert into orders (product, qty) values ('tea', 2), ('x', 3) returning id",
    "insert into audit (message) values ('x')",
    "update orders as o set qty = o.qty + 1 where o.id = 1 returning *",
    "delete from orders where id in (select id from customers) returning id, product",
];

/// Fragments to splice into the seeds: things the policy forbids, and syntax that might confuse a parser.
pub const FRAGMENTS: &[&str] = &[
    " secrets ",
    " secret ",
    " pg_shadow ",
    " pg_catalog.pg_class ",
    " information_schema.tables ",
    " public.",
    " pg_sleep(1) ",
    " pg_read_file('/etc/passwd') ",
    " version() ",
    " current_user ",
    " set_config('a','b',false) ",
    " ctid ",
    " xmin ",
    " tableoid ",
    " orders.* ",
    " orders ",
    " o ",
    " c ",
    " v ",
    " limited ",
    " audit ",
    "'",
    "''",
    "\\'",
    "\\",
    "\"",
    "\"\"",
    "$$",
    "$a$",
    "$1",
    "E'",
    "U&'",
    "X'",
    "N'",
    "B'",
    "_x '",
    "--",
    "/*",
    "*/",
    "/*+",
    ";",
    ",",
    ".",
    "(",
    ")",
    "((",
    "))",
    "*",
    "::",
    "::regclass",
    "::text",
    " OPERATOR(pg_catalog.=) ",
    " ~ ",
    " !~* ",
    " similar to ",
    " || ",
    " -> ",
    " ->> ",
    " @> ",
    " # ",
    " ! ",
    " @ ",
    " union ",
    " union all ",
    " intersect ",
    " except ",
    " select ",
    " from ",
    " where ",
    " and ",
    " or ",
    " not ",
    " group by ",
    " order by ",
    " having ",
    " limit ",
    " offset ",
    " returning ",
    " as ",
    " on ",
    " using (id) ",
    " join ",
    " left join ",
    " natural join ",
    " cross join ",
    " lateral ",
    " with ",
    " recursive ",
    " into ",
    " for update ",
    " in ",
    " exists ",
    " between ",
    " like ",
    " is null ",
    " is not distinct from ",
    " case ",
    " when ",
    " then ",
    " else ",
    " end ",
    " over ",
    " partition by ",
    " filter ",
    " distinct ",
    " all ",
    " any ",
    " values ",
    " set ",
    " default ",
    " null ",
    " true ",
    " 1 ",
    " 0 ",
    " -1 ",
    " 1e400 ",
    " 1L ",
    " 0x1 ",
    " insert into ",
    " update ",
    " delete from ",
    " table ",
    " only ",
    " tablesample ",
    " collate \"C\" ",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "\0",
    "\u{a0}",
    "\u{feff}",
    " coalesce(",
    " count(",
    " lower(",
    " nullif(",
    " current_date ",
    " extract(",
    " trim(",
    " substring(",
    " cast(",
];
