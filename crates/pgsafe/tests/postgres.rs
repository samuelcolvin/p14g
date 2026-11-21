//! Run pgsafe's output against a real Postgres, as a role whose grants say the same thing as the policy.
//!
//! Postgres is the oracle. If pgsafe accepts a statement and Postgres then refuses it for lack of
//! privilege, pgsafe let through something the policy does not allow; if Postgres cannot parse it, the
//! writer is wrong. Either fails the test.
//!
//! Needs `PGSAFE_TEST_DATABASE_URL` pointing at a superuser connection, and is skipped without it. It
//! drops and recreates a database called `pgsafe_test` and a role called `pgsafe_test_role`.

mod common;

use std::env;

use common::{accept_cases, params_policy, policy};
use pgsafe::{Literals, Policy};
use postgres::{Client, Config, NoTls, SimpleQueryMessage, error::SqlState};

const ROLE: &str = "pgsafe_test_role";

fn connect() -> Option<Client> {
    let url = env::var("PGSAFE_TEST_DATABASE_URL").ok()?;
    let mut config: Config = url
        .parse()
        .expect("PGSAFE_TEST_DATABASE_URL is not a valid connection string");
    let mut admin = config
        .connect(NoTls)
        .expect("cannot connect to PGSAFE_TEST_DATABASE_URL");
    // one statement at a time: DROP DATABASE cannot run in the implicit transaction of a batch
    for statement in [
        "DROP DATABASE IF EXISTS pgsafe_test".to_owned(),
        format!("DROP ROLE IF EXISTS {ROLE}"),
        format!("CREATE ROLE {ROLE}"),
        "CREATE DATABASE pgsafe_test".to_owned(),
    ] {
        admin.batch_execute(&statement).unwrap();
    }
    config.dbname("pgsafe_test");
    let mut client = config.connect(NoTls).unwrap();
    client.batch_execute(include_str!("cases/schema.sql")).unwrap();
    Some(client)
}

/// Run one statement as the restricted role and roll it back. Returns the number of rows it produced.
fn run(client: &mut Client, sql: &str, params: &[String]) -> Result<usize, postgres::Error> {
    let mut transaction = client.transaction()?;
    transaction.batch_execute(&format!("SET LOCAL ROLE {ROLE}"))?;
    let count = |messages: Vec<SimpleQueryMessage>| {
        messages
            .iter()
            .filter(|message| matches!(message, SimpleQueryMessage::Row(_)))
            .count()
    };
    let rows = if params.is_empty() {
        count(transaction.simple_query(sql)?)
    } else {
        // Send the values as untyped text, the way psycopg does. The `postgres` crate would send them in
        // binary as whatever type the server inferred, which a `String` cannot be for a date or an integer.
        // a prepared statement outlives the rollback
        transaction.simple_query(&format!("DEALLOCATE ALL; PREPARE pgsafe_p AS {sql}"))?;
        let values: Vec<String> = params.iter().map(|p| format!("$pgsafe_v${p}$pgsafe_v$")).collect();
        count(transaction.simple_query(&format!("EXECUTE pgsafe_p({})", values.join(", ")))?)
    };
    transaction.rollback()?;
    Ok(rows)
}

#[test]
fn postgres_agrees() {
    let Some(mut client) = connect() else {
        return;
    };

    // the oracle only means something if the role really is restricted
    for forbidden in [
        "SELECT secret FROM orders",
        "SELECT * FROM secrets",
        "SELECT email FROM customers",
        "UPDATE orders SET product = 'x' WHERE id = 1",
        "INSERT INTO customers (id, name) VALUES (9, 'x')",
        "SELECT hidden FROM app.events",
        "SELECT id FROM audit",
    ] {
        let error = run(&mut client, forbidden, &[]).expect_err(forbidden);
        assert_eq!(error.code().map(SqlState::code), Some("42501"), "{forbidden}");
    }

    let inline = policy();
    let params = params_policy();
    let mut failures = Vec::new();
    let mut indeterminate = 0;
    for case in accept_cases() {
        // statements with their own placeholders need values pgsafe does not have
        if case.sql.contains('$') && !case.sql.contains("$$") && !case.sql.contains("$tag$") {
            continue;
        }
        let safe = inline.check(case.sql, &()).unwrap();
        let inline_rows = match run(&mut client, &safe.sql, &[]) {
            Ok(rows) => rows,
            Err(e) => {
                failures.push(format!("line {}: {}\n  {}", case.line, safe.sql, describe(&e)));
                continue;
            }
        };
        let safe = params.check(case.sql, &()).unwrap();
        match run(&mut client, &safe.sql, &safe.params) {
            Ok(rows) if rows == inline_rows => {}
            Ok(rows) => failures.push(format!(
                "line {}: {} rows with params, {inline_rows} inline\n  {}",
                case.line, rows, safe.sql
            )),
            // A parameter has no type of its own, so Postgres cannot pass one to a function that takes
            // any type (`concat`), where it would have read an inline literal as text. That is how
            // parameters work, not something pgsafe can fix without changing what other statements mean.
            Err(e) if e.code().map(SqlState::code) == Some("42P18") => indeterminate += 1,
            Err(e) => failures.push(format!("line {} (params): {}\n  {}", case.line, safe.sql, describe(&e))),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        indeterminate <= 2,
        "{indeterminate} statements could not run with parameters"
    );

    literals_round_trip(&mut client);
    identifiers_round_trip(&mut client);
    views_enforce_rows(&mut client);
    star_allow(&mut client);
    only_leaves_out_children(&mut client);
    default_schema_is_not_shadowed(&mut client);
}

const NASTY: &[&str] = &[
    "",
    "plain",
    "it's",
    "''",
    "'",
    "\\",
    "\\'",
    "\\\\'",
    "x\\' UNION SELECT password FROM secrets --",
    "'; DROP TABLE orders; --",
    "a\\",
    "E'x'",
    "$1 $$ $tag$",
    "/* comment */ -- more",
    "line\nbreak\ttab\rreturn",
    "\u{1F600} \u{e9} \u{5c0f}",
    "\\x41 \\101 \\u0041 \\n",
    "%_\\%",
    "\"double\"",
];

/// A string that goes through pgsafe as a literal comes back from Postgres unchanged, whatever
/// `standard_conforming_strings` is set to.
fn literals_round_trip(client: &mut Client) {
    let inline = policy();
    let params = params_policy();
    for conforming in ["on", "off"] {
        client
            .batch_execute(&format!(
                "SET standard_conforming_strings = {conforming}; SET escape_string_warning = off"
            ))
            .unwrap();
        for value in NASTY {
            // dollar quoting carries any string into the input with no escaping to get wrong
            let input = format!("select $pgsafe_q${value}$pgsafe_q$");
            let safe = inline.check(&input, &()).unwrap();
            let row = client
                .query_one(&safe.sql, &[])
                .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
            assert_eq!(row.get::<_, &str>(0), *value, "{} with scs={conforming}", safe.sql);

            // and the usual quoted form, which is only the same string when backslashes are not escapes
            let input = format!("select '{}'", value.replace('\'', "''"));
            let safe = inline.check(&input, &()).unwrap();
            let row = client
                .query_one(&safe.sql, &[])
                .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
            assert_eq!(row.get::<_, &str>(0), *value, "{} with scs={conforming}", safe.sql);

            let safe = params.check(&input, &()).unwrap();
            assert_eq!(safe.sql, "SELECT $1");
            assert_eq!(safe.params, [*value]);
        }
    }
    client.batch_execute("RESET standard_conforming_strings").unwrap();
}

/// A quoted identifier comes back from Postgres as the same name.
fn identifiers_round_trip(client: &mut Client) {
    let policy = policy();
    for name in [
        "plain",
        "MiXed",
        "with space",
        "a\"b",
        "\"\"",
        "semi;colon",
        "dash--dash",
        "back\\slash",
        "q'uote",
        "$1",
    ] {
        let input = format!("select 1 as \"{}\"", name.replace('"', "\"\""));
        let safe = policy.check(&input, &()).unwrap();
        let row = client
            .query_one(&safe.sql, &[])
            .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
        assert_eq!(row.columns()[0].name(), name, "{}", safe.sql);
    }
}

/// The recipe from the README: rows are restricted by a view, and that holds for writes too.
fn views_enforce_rows(client: &mut Client) {
    let policy = policy();
    let run_ok = |client: &mut Client, sql: &str| {
        let safe = policy.check(sql, &()).unwrap();
        run(client, &safe.sql, &[])
    };
    // only the two orders with qty < 10 are visible or writable through the view
    assert_eq!(run_ok(client, "select * from cheap_orders").unwrap(), 2);
    assert_eq!(
        run_ok(client, "update cheap_orders set qty = 1 where true returning id").unwrap(),
        2
    );
    assert_eq!(
        run_ok(client, "delete from cheap_orders where true returning id").unwrap(),
        2
    );
    // WITH CHECK OPTION: a row cannot be moved, or created, outside the view
    for sql in [
        "update cheap_orders set qty = 50 where product = 'tea'",
        "insert into cheap_orders (product, qty) values ('gold', 500)",
    ] {
        let error = run_ok(client, sql).expect_err(sql);
        assert_eq!(error.code().map(SqlState::code), Some("44000"), "{sql}");
    }
}

/// `Star::Allow` passes `*` through, which is only sound because it is refused for tables with a column list.
fn star_allow(client: &mut Client) {
    let policy: Policy = common::builder()
        .star_behaviour(pgsafe::Star::Allow)
        .literals(Literals::Inline)
        .build()
        .unwrap();
    let safe = policy.check("select * from v", &()).unwrap();
    assert_eq!(safe.sql, r#"SELECT * FROM "v""#);
    assert_eq!(run(client, &safe.sql, &[]).unwrap(), 3);
    assert!(policy.check("select * from orders", &()).is_err());
}

fn describe(error: &postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {}", db.code().code(), db.message()),
        None => error.to_string(),
    }
}

/// A rule with `only` keeps reads and writes to the table itself; without it Postgres includes the rows
/// of tables that inherit from it, though the role has no privilege on those.
fn only_leaves_out_children(client: &mut Client) {
    let error = run(client, "SELECT id FROM family_child", &[]).expect_err("the child is not granted");
    assert_eq!(error.code().map(SqlState::code), Some("42501"));
    // what Postgres does with the plain table name: two rows of its own and three of the child's
    assert_eq!(run(client, r#"SELECT "id" FROM "family""#, &[]).unwrap(), 5);
    assert_eq!(run(client, r#"DELETE FROM "family" RETURNING "id""#, &[]).unwrap(), 5);

    let policy = policy();
    let mut rows = |sql: &str| {
        let safe = policy.check(sql, &()).unwrap();
        assert!(safe.sql.contains(r#"ONLY "family""#), "{}", safe.sql);
        run(client, &safe.sql, &[]).unwrap()
    };
    assert_eq!(rows("select * from family"), 2);
    assert_eq!(rows("select id from family where label = 'child'"), 0);
    assert_eq!(rows("update family set label = 'x' where true returning id"), 2);
    assert_eq!(rows("delete from family where true returning id"), 2);
}

/// With `default_schema`, a temporary table of the same name does not take the place of the real one.
fn default_schema_is_not_shadowed(client: &mut Client) {
    let qualified = common::builder().default_schema("public").build().unwrap();
    let plain = policy();
    let sql = "select id from customers";
    let rows = |client: &mut Client, policy: &Policy| {
        let safe = policy.check(sql, &()).unwrap();
        let messages = client.simple_query(&safe.sql).unwrap();
        messages
            .iter()
            .filter(|m| matches!(m, SimpleQueryMessage::Row(_)))
            .count()
    };
    assert_eq!(rows(client, &qualified), 2);
    assert_eq!(rows(client, &plain), 2);

    client
        .batch_execute("CREATE TEMPORARY TABLE customers (id int)")
        .unwrap();
    // Postgres looks in the temporary schema first, so the unqualified name now means the empty table
    assert_eq!(rows(client, &plain), 0);
    assert_eq!(rows(client, &qualified), 2);
    client.batch_execute("DROP TABLE pg_temp.customers").unwrap();

    // writes and RETURNING work on the qualified name too
    for sql in [
        "insert into orders (product, qty) values ('x', 1) returning id",
        "update orders set qty = 2 where id = 1 returning *",
        "delete from orders where id = 1 returning id",
    ] {
        let safe = qualified.check(sql, &()).unwrap();
        assert!(safe.sql.contains(r#""public"."orders""#), "{}", safe.sql);
        assert_eq!(run(client, &safe.sql, &[]).unwrap(), 1, "{}", safe.sql);
    }
}
