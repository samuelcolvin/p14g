//! The properties both fuzz targets check.
//!
//! Whatever the input, `Policy::rewrite` must not panic. When it accepts a statement:
//!
//! * Postgres's own parser (`libpg_query`) must parse the output as one `SELECT`, `INSERT`, `UPDATE` or `DELETE`
//!   that calls no `set_config` and updates no `pg_settings`, so it cannot change the role it runs as. Nothing
//!   matters more than this;
//! * that statement must only name tables and functions the policy allows;
//! * p14g reading its own output back must produce the same SQL again;
//! * if `P14G_TEST_DATABASE_URL` is set, Postgres itself must be willing to plan the output for a role
//!   that has been granted exactly what the policy allows, and doing so must leave the role and settings as
//!   they were.
//!
//! The last is the only one that sees columns. `EXPLAIN` runs Postgres's permission checks without running
//! the statement, so a column, table or whole-row reference that p14g let through but the grants do not
//! cover comes back as "permission denied".

use std::{
    collections::BTreeSet,
    env,
    sync::{LazyLock, Mutex},
};

use p14g::{Delete, ErrorKind, Filter, Insert, Literals, Policy, PolicyBuilder, Select, Update, functions};
use pg_query::{NodeEnum, ParseResult};
use postgres::{Client, Config, NoTls, SimpleQueryMessage, error::SqlState};
use serde_json::Value;

/// The same shape of policy as the test suite: column lists, an all-columns view, a schema-qualified
/// table, and writes.
fn builder() -> PolicyBuilder {
    Policy::builder()
        .select(Select::table("orders").columns(["id", "product", "qty", "customer_id"]))
        .select(Select::table("customers").columns(["id", "name"]))
        .select(Select::table("v"))
        .select(Select::table("app.events").columns(["id", "kind"]))
        .select(Select::table("limited").columns(["a", "b"]))
        .insert(Insert::table("orders").columns(["product", "qty"]))
        .insert(Insert::table("audit").columns(["message"]))
        .update(Update::table("orders").columns(["qty"]))
        .delete(Delete::table("orders"))
        // a table whose rules have a filter, reading a column the statement may not
        .select(
            Select::table("scoped")
                .columns(["id", "val"])
                .filter(|()| scoped_filter()),
        )
        .update(Update::table("scoped").columns(["val"]).filter(|()| scoped_filter()))
        .delete(Delete::table("scoped").filter(|()| scoped_filter()))
}

fn scoped_filter() -> Filter {
    Filter::new("org = :org and kind in (:kinds)")
        .bind("org", 7)
        .bind("kinds", vec!["a", "b'c"])
}

const TABLES: &[&str] = &["orders", "customers", "v", "app.events", "limited", "audit", "scoped"];

static INLINE: LazyLock<Policy> = LazyLock::new(|| builder().build().unwrap());
static PARAMS: LazyLock<Policy> = LazyLock::new(|| builder().literals(Literals::Params).build().unwrap());

const ROLE: &str = "p14g_fuzz_role";

/// Tables for the fuzz policy, each with columns the policy does not allow, and one table it does not
/// name at all. Every statement can be repeated, because fuzz processes share the database.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS customers (id int, name text, email text);
    CREATE TABLE IF NOT EXISTS orders (
        id int, product text, qty int, customer_id int, tenant_id int, secret text, created timestamptz, data jsonb
    );
    CREATE OR REPLACE VIEW v AS SELECT id, product, qty, created, data FROM orders;
    CREATE SCHEMA IF NOT EXISTS app;
    CREATE TABLE IF NOT EXISTS app.events (id int, kind text, hidden text);
    CREATE TABLE IF NOT EXISTS limited (a int, b int, c int);
    CREATE TABLE IF NOT EXISTS audit (id int, message text, tenant_id int);
    CREATE TABLE IF NOT EXISTS secrets (id int, password text);
    CREATE TABLE IF NOT EXISTS scoped (id int, val text, org int, kind text, hidden text);
    DO $$ BEGIN CREATE ROLE p14g_fuzz_role; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
";

/// Who the session is and the settings that decide what it can reach.
const IDENTITY: &str = "SELECT current_user, session_user, current_setting('role'), \
    current_setting('search_path'), current_setting('row_security'), current_setting('session_replication_role')";

fn identity(client: &mut Client) -> Vec<Option<String>> {
    let messages = client.simple_query(IDENTITY).expect(IDENTITY);
    let row = messages
        .iter()
        .find_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(row),
            _ => None,
        })
        .expect(IDENTITY);
    (0..row.len()).map(|i| row.get(i).map(str::to_owned)).collect()
}

struct Database {
    client: Client,
    /// [`IDENTITY`] once the connection has switched to the restricted role.
    identity: Vec<Option<String>>,
}

/// A connection acting as a role with the grants the fuzz policy generates, or `None` without a database.
static DATABASE: LazyLock<Option<Mutex<Database>>> = LazyLock::new(|| {
    let url = env::var("P14G_TEST_DATABASE_URL").ok()?;
    let mut config: Config = url
        .parse()
        .expect("P14G_TEST_DATABASE_URL is not a valid connection string");
    let mut admin = config.connect(NoTls).expect("cannot connect to P14G_TEST_DATABASE_URL");
    if let Err(e) = admin.batch_execute("CREATE DATABASE p14g_fuzz") {
        assert_eq!(e.code(), Some(&SqlState::DUPLICATE_DATABASE), "{e}");
    }
    config.dbname("p14g_fuzz");
    let mut client = config.connect(NoTls).unwrap();
    // other fuzz processes may be doing the same setup, and concurrent GRANTs on one table fail
    client.batch_execute("SELECT pg_advisory_lock(7347)").unwrap();
    client.batch_execute(SCHEMA).unwrap();
    for grant in INLINE.grants(ROLE, &()).unwrap() {
        client.batch_execute(&grant).unwrap();
    }
    client.batch_execute("SELECT pg_advisory_unlock(7347)").unwrap();
    client
        .batch_execute(&format!("SET ROLE {ROLE}; SET statement_timeout = '2s'"))
        .unwrap();
    let identity = identity(&mut client);
    assert_eq!(identity[0].as_deref(), Some(ROLE));
    Some(Mutex::new(Database { client, identity }))
});

/// Ask Postgres to plan `output` as the restricted role, then check the session is still that role.
///
/// Most errors mean nothing here: the fuzzer writes statements that are allowed but wrong, such as a text
/// column added to a number, and the view `v` accepts any column name. Three do mean p14g got it wrong.
fn explain(input: &str, output: &str) {
    let Some(database) = &*DATABASE else {
        return;
    };
    let mut database = database.lock().unwrap();
    let result = database.client.simple_query(&format!("EXPLAIN {output}"));
    if let Err(error) = &result
        && error.as_db_error().is_none()
    {
        panic!("lost the connection to Postgres: {error}");
    }
    let now = identity(&mut database.client);
    assert_eq!(
        now, database.identity,
        "the role or a setting changed\n input: {input}\noutput: {output}"
    );
    let Err(error) = result else {
        return;
    };
    let db_error = error.as_db_error().expect("checked above");
    let problem = match db_error.code() {
        code if *code == SqlState::INSUFFICIENT_PRIVILEGE => "Postgres refused something the policy allowed",
        code if *code == SqlState::SYNTAX_ERROR => "Postgres cannot parse the output",
        code if *code == SqlState::UNDEFINED_TABLE => "the output names a table that does not exist",
        _ => return,
    };
    panic!("{problem}: {}\n input: {input}\noutput: {output}", db_error.message());
}

/// Every function call in `parsed`, as `schema.name` or `name`, wherever it is in the statement.
///
/// `ParseResult::functions()` and `nodes()` miss calls in `VALUES`, `RETURNING`, `FILTER`, `OVER`, `LIMIT`,
/// `ARRAY[...]` and under `COLLATE`, so this serializes the whole tree and looks at every node.
/// `tests/common/mod.rs` has the same function.
fn called_functions(parsed: &ParseResult) -> Vec<String> {
    fn walk(value: &Value, calls: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(call) = map.get("FuncCall") {
                    let names = call["funcname"].as_array().into_iter().flatten();
                    let names: Vec<&str> = names
                        .filter_map(|name| name.pointer("/node/String/sval").and_then(Value::as_str))
                        .collect();
                    calls.push(names.join("."));
                }
                map.values().for_each(|value| walk(value, calls));
            }
            Value::Array(values) => values.iter().for_each(|value| walk(value, calls)),
            _ => {}
        }
    }

    let tree = serde_json::to_value(&parsed.protobuf).expect("a parse tree serializes");
    let mut calls = Vec::new();
    walk(&tree, &mut calls);
    calls
}

/// Panic unless `parsed` is one `SELECT`, `INSERT`, `UPDATE` or `DELETE` that calls none of
/// [`functions::FORBIDDEN`] and names no `pg_settings`, whose `UPDATE` rule calls `set_config`.
///
/// Every other kind of statement is a utility statement or `MERGE`, and Postgres's grammar has no way to put one
/// inside these four. `tests/common/mod.rs` makes the same check on the test cases.
fn assert_cannot_change_role(parsed: &ParseResult, input: &str, output: &str) {
    assert_eq!(
        parsed.protobuf.stmts.len(),
        1,
        "more than one statement\n input: {input}\noutput: {output}"
    );
    let node = parsed.protobuf.stmts[0].stmt.as_ref().and_then(|stmt| stmt.node.as_ref());
    assert!(
        matches!(
            node,
            Some(NodeEnum::SelectStmt(_) | NodeEnum::InsertStmt(_) | NodeEnum::UpdateStmt(_) | NodeEnum::DeleteStmt(_))
        ),
        "not a SELECT, INSERT, UPDATE or DELETE\n input: {input}\noutput: {output}"
    );
    for function in called_functions(parsed) {
        assert!(
            !function.rsplit('.').next().is_some_and(functions::is_forbidden),
            "calls {function}\n input: {input}\noutput: {output}"
        );
    }
    for table in parsed.tables() {
        assert!(
            table.rsplit('.').next() != Some("pg_settings"),
            "names {table}\n input: {input}\noutput: {output}"
        );
    }
}

/// Run every check on one input.
pub fn check(sql: &str) {
    for policy in [&*INLINE, &*PARAMS] {
        let Ok(safe) = policy.rewrite(sql, &()) else {
            continue;
        };
        let parsed = pg_query::parse(&safe.sql).unwrap_or_else(|e| {
            panic!(
                "Postgres cannot parse the output\n input: {sql}\noutput: {}\n error: {e}",
                safe.sql
            )
        });
        assert_cannot_change_role(&parsed, sql, &safe.sql);

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
        for function in called_functions(&parsed) {
            // builtins are written by name; the grammar qualifies the ones it produces itself
            let name = function.strip_prefix("pg_catalog.").unwrap_or(&function);
            let allowed = functions::is_default(name) || name == "btrim" || name == "like_escape";
            assert!(
                allowed,
                "Postgres sees function {function:?}\n input: {sql}\noutput: {}",
                safe.sql
            );
        }

        // parameters are placeholders with no values here, so only the inline form can be planned
        if safe.params.is_empty() {
            explain(sql, &safe.sql);
        }

        // the output of a statement on a filtered table has the filter in it, and reading it back would
        // apply the filter a second time
        if safe.tables.iter().any(|table| table == "scoped") {
            assert!(
                safe.sql.contains(".org = 7 AND "),
                "the filter is missing\n input: {sql}\noutput: {}",
                safe.sql
            );
            continue;
        }

        match policy.rewrite(&safe.sql, &()) {
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
    "select s.id, o.id from scoped s left join orders o on o.id = s.id where s.val like 'a%' or true",
    "select id from orders where id in (select id from scoped) union select id from scoped",
    "update scoped set val = 'x' where id = 1 or true returning *",
    "delete from scoped as s where s.id > 0 returning s.val",
];

/// Fragments to splice into the seeds: things the policy forbids, and syntax that might confuse a parser.
pub const FRAGMENTS: &[&str] = &[
    " secrets ",
    " scoped ",
    " org ",
    " kind ",
    " secret ",
    " email ",
    " hidden ",
    " tenant_id ",
    " password ",
    " limited.c ",
    " pg_shadow ",
    " pg_catalog.pg_class ",
    " information_schema.tables ",
    " public.",
    " pg_sleep(1) ",
    " pg_read_file('/etc/passwd') ",
    " version() ",
    " current_user ",
    " set_config('a','b',false) ",
    // ways to change or reset the role, or the settings that decide what it reaches: see `tests/cases/role.sql`
    " set_config('role','none',false) ",
    " pg_catalog.set_config(",
    " query_to_xml('select 1',true,true,'') ",
    " ts_stat('select 1') ",
    " dblink_exec('','reset role') ",
    " \"set_config\"(",
    " pg_settings ",
    " pg_catalog.pg_settings ",
    "; reset role",
    "; set role none",
    "; set session authorization default",
    "; reset all",
    "; discard all",
    "; commit",
    "; rollback",
    "; rollback to a",
    " set role ",
    " set local role ",
    " reset ",
    " role ",
    " session authorization ",
    " search_path ",
    " row_security ",
    " set search_path = evil ",
    " discard all ",
    " begin ",
    " commit ",
    " rollback ",
    " savepoint a ",
    " grant ",
    " revoke ",
    " to public ",
    " alter role current_user ",
    " superuser ",
    " security definer ",
    " do $$ begin end $$ ",
    " call ",
    " execute ",
    " prepare ",
    " copy ",
    " program ",
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
