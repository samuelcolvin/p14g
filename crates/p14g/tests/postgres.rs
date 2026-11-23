//! Run p14g's output against a real Postgres, as a role whose grants say the same thing as the policy.
//!
//! Postgres is the oracle. If p14g accepts a statement and Postgres then refuses it for lack of
//! privilege, p14g let through something the policy does not allow; if Postgres cannot parse it, the
//! writer is wrong. Either fails the test.
//!
//! Needs `P14G_TEST_DATABASE_URL` pointing at a superuser connection, and is skipped without it. It
//! drops and recreates a database called `p14g_test` and a role called `p14g_test_role`.

mod common;

use std::{
    env,
    panic::{self, AssertUnwindSafe},
};

use common::{accept_cases, params_policy, policy};
use p14g::{Delete, Filter, Insert, Layout, Literals, Policy, QuoteIdentifiers, Select, Update, functions};
use postgres::{Client, Config, NoTls, SimpleQueryMessage, error::SqlState};

const ROLE: &str = "p14g_test_role";

fn connect() -> Option<Client> {
    let url = env::var("P14G_TEST_DATABASE_URL").ok()?;
    let mut config: Config = url
        .parse()
        .expect("P14G_TEST_DATABASE_URL is not a valid connection string");
    let mut admin = config.connect(NoTls).expect("cannot connect to P14G_TEST_DATABASE_URL");
    // one statement at a time: DROP DATABASE cannot run in the implicit transaction of a batch
    for statement in [
        "DROP DATABASE IF EXISTS p14g_test".to_owned(),
        format!("DROP ROLE IF EXISTS {ROLE}"),
        format!("CREATE ROLE {ROLE}"),
        "CREATE DATABASE p14g_test".to_owned(),
    ] {
        admin.batch_execute(&statement).unwrap();
    }
    config.dbname("p14g_test");
    let mut client = config.connect(NoTls).unwrap();
    client.batch_execute(include_str!("cases/schema.sql")).unwrap();
    Some(client)
}

/// Who the session is and the settings that decide what it can reach. No statement p14g accepts may change any
/// of them.
const IDENTITY: &str = "SELECT current_user, session_user, current_setting('role'), \
    current_setting('search_path'), current_setting('row_security'), current_setting('session_replication_role'), \
    current_setting('transaction_read_only')";

fn identity(transaction: &mut postgres::Transaction<'_>) -> Result<Vec<Option<String>>, postgres::Error> {
    let messages = transaction.simple_query(IDENTITY)?;
    let Some(row) = messages.iter().find_map(|message| match message {
        SimpleQueryMessage::Row(row) => Some(row),
        _ => None,
    }) else {
        panic!("no row from {IDENTITY}");
    };
    Ok((0..row.len()).map(|i| row.get(i).map(str::to_owned)).collect())
}

/// Run one statement as the restricted role and roll it back. Returns the number of rows it produced.
///
/// Panics if the statement changed the role or the settings in [`IDENTITY`].
fn run(client: &mut Client, sql: &str, params: &[String]) -> Result<usize, postgres::Error> {
    run_with(client, "", sql, params)
}

/// [`run`], after `setup` has run as the restricted role in the same transaction.
fn run_with(client: &mut Client, setup: &str, sql: &str, params: &[String]) -> Result<usize, postgres::Error> {
    let mut transaction = client.transaction()?;
    transaction.batch_execute(&format!("SET LOCAL ROLE {ROLE}; {setup}"))?;
    let before = identity(&mut transaction)?;
    assert_eq!(before[0].as_deref(), Some(ROLE));
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
        transaction.simple_query(&format!("DEALLOCATE ALL; PREPARE p14g_p AS {sql}"))?;
        let values: Vec<String> = params.iter().map(|p| format!("$p14g_v${p}$p14g_v$")).collect();
        count(transaction.simple_query(&format!("EXECUTE p14g_p({})", values.join(", ")))?)
    };
    let after = identity(&mut transaction)?;
    assert_eq!(before, after, "the role or a setting changed: {sql}");
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
        // statements with their own placeholders need values p14g does not have
        if case.sql.contains('$') && !case.sql.contains("$$") && !case.sql.contains("$tag$") {
            continue;
        }
        let safe = inline.rewrite(case.sql, &()).unwrap();
        let inline_rows = match run(&mut client, &safe.sql, &[]) {
            Ok(rows) => rows,
            Err(e) => {
                failures.push(format!("line {}: {}\n  {}", case.line, safe.sql, describe(&e)));
                continue;
            }
        };
        let safe = params.rewrite(case.sql, &()).unwrap();
        match run(&mut client, &safe.sql, &safe.params) {
            Ok(rows) if rows == inline_rows => {}
            Ok(rows) => failures.push(format!(
                "line {}: {} rows with params, {inline_rows} inline\n  {}",
                case.line, rows, safe.sql
            )),
            // A parameter has no type of its own, so Postgres cannot pass one to a function that takes
            // any type (`concat`), where it would have read an inline literal as text. That is how
            // parameters work, not something p14g can fix without changing what other statements mean.
            Err(e) if e.code().map(SqlState::code) == Some("42P18") => indeterminate += 1,
            Err(e) => failures.push(format!("line {} (params): {}\n  {}", case.line, safe.sql, describe(&e))),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        indeterminate <= 2,
        "{indeterminate} statements could not run with parameters"
    );

    role_changes_are_caught(&mut client);
    literals_round_trip(&mut client);
    identifiers_round_trip(&mut client);
    views_enforce_rows(&mut client);
    only_leaves_out_children(&mut client);
    default_schema_is_not_shadowed(&mut client);
    generated_grants(&mut client);
    keywords_and_quoting(&mut client);
    function_names(&mut client);
    filters_restrict_rows(&mut client);
    filters_are_not_a_security_barrier(&mut client);
}

/// `run` checks that every statement leaves the role and settings as they were. Make sure that check would see
/// statements that do change them, run directly rather than through p14g, which rejects them all
/// (`tests/role.rs`).
fn role_changes_are_caught(client: &mut Client) {
    for sql in [
        "RESET ROLE",
        "SET ROLE NONE",
        "SELECT set_config('role', 'none', true)",
        "SET LOCAL search_path = pg_catalog",
        "SET LOCAL row_security = off",
        // What p14g would write for `select reset_role from v` if a rule could allow every column: Postgres reads it
        // as `reset_role(v)`. The rule for `v` lists all of its columns, so the grants allow the whole row.
        "SELECT v.reset_role FROM v",
    ] {
        let result = panic::catch_unwind(AssertUnwindSafe(|| run(client, sql, &[])));
        assert!(result.is_err(), "the role check in `run` did not notice {sql}");
    }
    // The same on `orders`, whose rule leaves columns out: the call passes the whole row, which the grants refuse.
    // So the grants stop this only for tables where some column is not granted; p14g has to stop it everywhere.
    let sql = "SELECT orders.reset_role FROM orders";
    let error = run(client, sql, &[]).expect_err(sql);
    assert_eq!(
        error.code().map(SqlState::code),
        Some("42501"),
        "{sql}: {}",
        describe(&error)
    );
    // the panics dropped their transactions, which rolled them back
    let mut transaction = client.transaction().unwrap();
    transaction.batch_execute(&format!("SET LOCAL ROLE {ROLE}")).unwrap();
    assert_eq!(identity(&mut transaction).unwrap()[0].as_deref(), Some(ROLE));
    transaction.rollback().unwrap();
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

/// A string that goes through p14g as a literal comes back from Postgres unchanged, whatever
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
            let input = format!("select $p14g_q${value}$p14g_q$");
            let safe = inline.rewrite(&input, &()).unwrap();
            let row = client
                .query_one(&safe.sql, &[])
                .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
            assert_eq!(row.get::<_, &str>(0), *value, "{} with scs={conforming}", safe.sql);

            // and the usual quoted form, which is only the same string when backslashes are not escapes
            let input = format!("select '{}'", value.replace('\'', "''"));
            let safe = inline.rewrite(&input, &()).unwrap();
            let row = client
                .query_one(&safe.sql, &[])
                .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
            assert_eq!(row.get::<_, &str>(0), *value, "{} with scs={conforming}", safe.sql);

            let safe = params.rewrite(&input, &()).unwrap();
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
        let safe = policy.rewrite(&input, &()).unwrap();
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
        let safe = policy.rewrite(sql, &()).unwrap();
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
        let safe = policy.rewrite(sql, &()).unwrap();
        // `family` is a keyword in Postgres, so it stays quoted
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
        let safe = policy.rewrite(sql, &()).unwrap();
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
        let safe = qualified.rewrite(sql, &()).unwrap();
        assert!(safe.sql.contains("public.orders"), "{}", safe.sql);
        assert_eq!(run(client, &safe.sql, &[]).unwrap(), 1, "{}", safe.sql);
    }
}

/// The grants `Policy::grants` writes give a fresh role what the policy allows and no more: every accepted
/// statement runs as that role, and the statements the hand-written role was refused are refused again.
fn generated_grants(client: &mut Client) {
    const GENERATED: &str = "p14g_generated_role";
    let policy = policy();
    client
        .batch_execute(&format!("DROP ROLE IF EXISTS {GENERATED}; CREATE ROLE {GENERATED}"))
        .unwrap();
    for grant in policy.grants(GENERATED, &()).unwrap() {
        client.batch_execute(&grant).unwrap_or_else(|e| panic!("{grant}: {e}"));
    }
    // not derivable from the policy: the sequences behind the serial columns
    client
        .batch_execute(&format!(
            "GRANT USAGE ON SEQUENCE orders_id_seq, audit_id_seq TO {GENERATED}"
        ))
        .unwrap();

    let run_as = |client: &mut Client, sql: &str| -> Result<(), postgres::Error> {
        let mut transaction = client.transaction()?;
        transaction.batch_execute(&format!("SET LOCAL ROLE {GENERATED}"))?;
        transaction.simple_query(sql)?;
        transaction.rollback()
    };
    for forbidden in [
        "SELECT secret FROM orders",
        "SELECT tenant_id FROM orders",
        "SELECT * FROM secrets",
        "SELECT email FROM customers",
        "UPDATE orders SET product = 'x' WHERE id = 1",
        "INSERT INTO customers (id, name) VALUES (9, 'x')",
        "INSERT INTO orders (secret) VALUES ('x')",
        "SELECT hidden FROM app.events",
        "SELECT id FROM audit",
        "DELETE FROM customers",
        "SELECT c FROM limited",
    ] {
        let error = run_as(client, forbidden).expect_err(forbidden);
        assert_eq!(error.code().map(SqlState::code), Some("42501"), "{forbidden}");
    }
    for case in accept_cases() {
        if case.sql.contains('$') && !case.sql.contains("$$") && !case.sql.contains("$tag$") {
            continue;
        }
        let safe = policy.rewrite(case.sql, &()).unwrap();
        run_as(client, &safe.sql).unwrap_or_else(|e| panic!("line {}: {}\n  {}", case.line, safe.sql, describe(&e)));
    }
}

/// Minimal quoting leaves a name bare only when Postgres reads it back as the same name. That depends on
/// p14g's keyword list being the server's, and on Postgres taking any word after a `.`.
fn keywords_and_quoting(client: &mut Client) {
    let server: Vec<String> = client
        .query("SELECT word FROM pg_get_keywords() ORDER BY word", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(server.len() > 400);

    // Every keyword, as a column name and as an alias, in both quoting modes, comes back as itself. A
    // keyword missing from p14g's list would be written bare where it is an alias, and Postgres would
    // read something else or refuse it.
    for quote in [QuoteIdentifiers::Minimal, QuoteIdentifiers::Always] {
        let policy: Policy = Policy::builder()
            // `t` is the CTE in each statement, which needs no rule
            .quote_identifiers(quote)
            .layout(Layout::Dense)
            .build()
            .unwrap();
        for word in &server {
            let sql = format!(r#"with t as (select 2 as "{word}") select t."{word}", 1 as "{word}" from t"#);
            let safe = policy.rewrite(&sql, &()).unwrap_or_else(|e| panic!("{sql}: {e}"));
            let row = client
                .query_one(&safe.sql, &[])
                .unwrap_or_else(|e| panic!("{}: {}", safe.sql, describe(&e)));
            assert_eq!(row.columns()[0].name(), word, "{}", safe.sql);
            assert_eq!(row.columns()[1].name(), word, "{}", safe.sql);
            assert_eq!((row.get::<_, i32>(0), row.get::<_, i32>(1)), (2, 1), "{}", safe.sql);
            if quote == QuoteIdentifiers::Minimal {
                // after a dot nothing is quoted, on its own every keyword is
                assert!(safe.sql.starts_with(&format!(
                    r#"WITH t AS (SELECT 2 AS "{word}") SELECT t.{word}, 1 AS "{word}""#
                )));
            }
        }
    }

    // names that are not plain lower case are quoted wherever they are
    let policy: Policy = Policy::builder().layout(Layout::Dense).build().unwrap();
    for name in [
        "MiXed",
        "with space",
        "1starts_with_digit",
        "a\"b",
        "caf\u{e9}",
        "dollar$",
    ] {
        let quoted = name.replace('"', "\"\"");
        let sql = format!(r#"with t as (select 2 as "{quoted}") select t."{quoted}", 1 as "{quoted}" from t"#);
        let safe = policy.rewrite(&sql, &()).unwrap();
        assert!(safe.sql.contains(&format!(r#"t."{quoted}""#)), "{}", safe.sql);
        let row = client
            .query_one(&safe.sql, &[])
            .unwrap_or_else(|e| panic!("{}: {e}", safe.sql));
        assert_eq!((row.columns()[0].name(), row.columns()[1].name()), (name, name));
    }
}

/// A function name is written bare unless Postgres would not read it as one. For every keyword on the
/// server, a call to a function of that name must get as far as "no such function", in both quoting modes
/// and with and without the schema: a syntax error means the name needed quotes it did not get.
fn function_names(client: &mut Client) {
    let keywords: Vec<String> = client
        .query("SELECT word FROM pg_get_keywords() ORDER BY word", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    for quote in [QuoteIdentifiers::Minimal, QuoteIdentifiers::Always] {
        let policy: Policy = Policy::builder()
            .functions(keywords.iter().map(|word| format!("nowhere.{word}")))
            .functions(keywords.iter().filter(|word| !functions::is_default(word)))
            .quote_identifiers(quote)
            .build()
            .unwrap();
        for word in &keywords {
            for call in [
                format!(r#"select "{word}"(1, 2, 3, 4, 5)"#),
                format!(r#"select nowhere."{word}"(1)"#),
            ] {
                let Ok(safe) = policy.rewrite(&call, &()) else {
                    // the keyword forms (COALESCE and the rest) take a fixed shape, which this is not
                    continue;
                };
                // these three are grammar under their own name, so the call is real and it runs
                if safe.sql.starts_with("SELECT COALESCE(")
                    || safe.sql.starts_with("SELECT GREATEST(")
                    || safe.sql.starts_with("SELECT LEAST(")
                {
                    client.simple_query(&safe.sql).unwrap();
                    continue;
                }
                let error = client.simple_query(&safe.sql).expect_err(&safe.sql);
                let code = error.code().map(SqlState::code);
                // 42883: no function of that name and arguments. 3F000: no schema called `nowhere`.
                assert!(
                    matches!(code, Some("42883" | "3F000")),
                    "{}: {}",
                    safe.sql,
                    describe(&error)
                );
            }
        }
    }

    // and with an empty `search_path` and every table qualified, which the docs recommend, every accepted
    // statement still runs: nothing p14g writes needs a function, operator or type outside `pg_catalog`
    let qualified: Policy = common::builder().default_schema("public").build().unwrap();
    for case in accept_cases() {
        if case.sql.contains('$') && !case.sql.contains("$$") && !case.sql.contains("$tag$") {
            continue;
        }
        let safe = qualified.rewrite(case.sql, &()).unwrap();
        run_with(client, "SET LOCAL search_path = ''", &safe.sql, &[])
            .unwrap_or_else(|e| panic!("line {}: {}\n  {}", case.line, safe.sql, describe(&e)));
    }
}

/// A rule's filter holds for reads through joins and subqueries, and for updates and deletes, whatever the
/// statement's own conditions say.
fn filters_restrict_rows(client: &mut Client) {
    let org = |org: &i64| Filter::new("org = :org").bind("org", *org);
    let policy: Policy<i64> = Policy::builder()
        .layout(Layout::Dense)
        .select(Select::table("scoped", ["id", "val"]).filter(org))
        .select(Select::table("customers", ["id", "name"]))
        .insert(
            Insert::table("scoped")
                .columns(["id", "val"])
                .extra(|org: &i64| [("org", *org)]),
        )
        .update(
            Update::table("scoped")
                .columns(["val"])
                .allow_unfiltered(true)
                .filter(org),
        )
        .delete(Delete::table("scoped").allow_unfiltered(true).filter(org))
        .build()
        .unwrap();
    // org 1 has two rows and org 2 has three; the role itself may read and write them all
    assert_eq!(run(client, "SELECT id FROM scoped", &[]).unwrap(), 5);

    let mut rows = |org: i64, sql: &str| {
        let safe = policy.rewrite(sql, &org).unwrap_or_else(|e| panic!("{sql}: {e}"));
        run(client, &safe.sql, &[]).unwrap_or_else(|e| panic!("{}: {}", safe.sql, describe(&e)))
    };
    for (org, count) in [(1, 2), (2, 3), (3, 0)] {
        assert_eq!(rows(org, "select * from scoped"), count);
        assert_eq!(rows(org, "select id from scoped where true or id > 0"), count);
        assert_eq!(
            rows(org, "select s.id from scoped s where s.id in (select id from scoped)"),
            count
        );
        assert_eq!(
            rows(org, "select 1 from scoped union all select 1 from scoped"),
            count * 2
        );
        // the nullable side of an outer join is where a condition added to WHERE would go wrong
        assert_eq!(
            rows(
                org,
                "select c.id, s.id from customers c left join scoped s on true where s.id is not null"
            ),
            count * 2
        );
        assert_eq!(
            rows(
                org,
                "select c.id from customers c left join scoped s on true where s.id is null"
            ),
            if count == 0 { 2 } else { 0 }
        );
        assert_eq!(
            rows(org, "select a.id from scoped a join scoped b on true"),
            count * count
        );
        assert_eq!(rows(org, "update scoped set val = 'x' returning id"), count);
        assert_eq!(
            rows(org, "update scoped set val = 'x' where true or id = 999 returning id"),
            count
        );
        assert_eq!(rows(org, "delete from scoped returning id"), count);
        assert_eq!(
            rows(org, "delete from scoped as s where s.id > 0 or true returning s.id"),
            count
        );
        assert_eq!(
            rows(org, "insert into scoped (id, val) values (100, 'new') returning id"),
            1
        );
    }
    // the generated grants cover the column the filter reads
    assert!(
        policy
            .grants("someone", &1)
            .unwrap()
            .contains(&r#"GRANT SELECT ("id", "val", "org") ON "scoped" TO "someone""#.to_owned())
    );
}

/// The README's warning about filters: Postgres may evaluate the statement's own conditions on a row before
/// the filter's, so whether a statement fails can depend on rows the filter excludes. Row-level security
/// evaluates its condition first, and closes that.
///
/// The leak depends on the planner's cost estimates: a filter that costs more than the statement's condition
/// is evaluated after it. If a Postgres release changes that, this test fails, and the README should be
/// checked rather than the test relaxed.
fn filters_are_not_a_security_barrier(client: &mut Client) {
    // a user who belongs to org 1 and to orgs that have no rows; eight values make `IN` cost more than the
    // statement's condition
    const ORGS: [i64; 8] = [1, 11, 12, 13, 14, 15, 16, 17];
    let policy: Policy = Policy::builder()
        .layout(Layout::Dense)
        .literals(Literals::Inline)
        .select(
            Select::table("scoped", ["id", "val"])
                .filter(|()| Filter::new("org in (:orgs)").bind("orgs", ORGS.to_vec())),
        )
        .select(Select::table("scoped_rls", ["id", "val"]))
        .build()
        .unwrap();
    let run_with_rls = |client: &mut Client, sql: &str| -> Result<usize, postgres::Error> {
        let safe = policy.rewrite(sql, &()).unwrap_or_else(|e| panic!("{sql}: {e}"));
        let mut transaction = client.transaction()?;
        let orgs = ORGS.map(|org| org.to_string()).join(",");
        transaction.batch_execute(&format!("SET LOCAL ROLE {ROLE}; SET LOCAL p14g.orgs = '{orgs}'"))?;
        let rows = transaction
            .simple_query(&safe.sql)?
            .iter()
            .filter(|message| matches!(message, SimpleQueryMessage::Row(_)))
            .count();
        transaction.rollback()?;
        Ok(rows)
    };

    // the filter hides rows 3 to 5, which belong to org 2
    assert_eq!(run_with_rls(client, "select id from scoped").unwrap(), 2);
    assert_eq!(
        run_with_rls(client, "select id from scoped where 1 / (id - 99) > 0").unwrap(),
        0
    );
    // but dividing by zero on row 3 fails the statement, which says that row 3 exists in another org
    let sql = "select id from scoped where 1 / (id - 3) > 0";
    let error = run_with_rls(client, sql).expect_err(sql);
    assert_eq!(error.code().map(SqlState::code), Some("22012"), "{sql}");

    // row-level security hides the same rows, and the same statement cannot see past it
    assert_eq!(run_with_rls(client, "select id from scoped_rls").unwrap(), 2);
    for id in [3, 4, 5, 99] {
        let sql = format!("select id from scoped_rls where 1 / (id - {id}) > 0");
        assert_eq!(run_with_rls(client, &sql).unwrap(), 0, "{sql}");
    }
}
