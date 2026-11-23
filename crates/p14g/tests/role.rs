//! Nothing p14g accepts may change, reset or get around the role its output runs as.
//!
//! This is the restriction everything else rests on: the grants and row-level security the caller set up
//! apply to a role, and a statement that can leave that role has neither. The cases are in `cases/role.sql`;
//! `postgres.rs` also checks, after every accepted statement, that the role and settings are unchanged.

mod common;

use std::panic;

use common::{assert_cannot_change_role, builder, policy, role_cases};
use p14g::{Dialect, Insert, Literals, Policy, Select, Update, functions};

#[test]
fn role_cases_are_rejected() {
    let policy = policy();
    let mut failures = Vec::new();
    for case in role_cases() {
        match policy.rewrite(case.sql, &()) {
            Ok(safe) => failures.push(format!("line {}: {}\n  accepted as: {}", case.line, case.sql, safe.sql)),
            Err(e) if e.kind() != case.kind => failures.push(format!(
                "line {}: {}\n  expected {:?}, got {:?}: {e}",
                case.line,
                case.sql,
                case.kind,
                e.kind()
            )),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The error kind can differ between dialects, since sqlparser parses some of these statements in one and not
/// another. A dialect can also read a case as something else: in MySQL `'x\'; reset role --'` is one string. So a
/// case may be accepted, but only as a statement that cannot change the role.
#[test]
fn role_cases_are_rejected_in_every_dialect() {
    let mut accepted = Vec::new();
    for dialect in [
        Dialect::Postgres,
        Dialect::Generic,
        Dialect::Ansi,
        Dialect::MySql,
        Dialect::Sqlite,
    ] {
        let policies = [
            builder().dialect(dialect).build().unwrap(),
            builder().dialect(dialect).literals(Literals::Params).build().unwrap(),
        ];
        for policy in &policies {
            for case in role_cases() {
                if let Ok(safe) = policy.rewrite(case.sql, &()) {
                    assert_cannot_change_role(&safe.sql, &format!("line {} ({dialect:?})", case.line));
                    accepted.push(format!("line {} ({dialect:?}): {}", case.line, case.sql));
                }
            }
        }
    }
    // the one case above, in the three MySQL policies
    assert!(accepted.len() <= 3, "{}", accepted.join("\n"));
}

/// Postgres reads `t.name` as the call `name(t)` when `t` has no column `name`, so p14g only writes names a rule
/// lists, and a select rule has to list its columns.
#[test]
fn select_rules_list_their_columns() {
    let error = Policy::<()>::builder()
        .select(Select::table("orders", Vec::<String>::new()))
        .build()
        .err()
        .unwrap();
    assert!(error.message().contains("lists no columns"), "{error}");
    for columns in [vec!["*"], vec!["id", " * "]] {
        let error = Policy::<()>::builder()
            .select(Select::table("orders", columns))
            .build()
            .err()
            .unwrap();
        assert_eq!(
            error.message(),
            "the select rule for table \"orders\" lists \"*\": for security reasons a select rule must list each column \
             it allows by name, see \"Why every column is listed\" in the README"
        );
    }
    let error = Policy::<()>::builder()
        .update(Update::table("orders").columns(["*"]))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        error.message(),
        "the rule for table \"orders\" lists \"*\": leave out `columns` to allow every column"
    );
    assert!(
        Policy::<()>::builder()
            .insert(Insert::table("orders").columns(["*"]))
            .build()
            .is_err()
    );

    let policy = policy();
    for sql in [
        "select reset_role from orders",
        "select o.reset_role from orders o",
        "select v.row_to_json from v",
        "select id from v order by v.to_jsonb",
        "select count(*) from customers group by customers.reset_role",
    ] {
        let error = policy.rewrite(sql, &()).unwrap_err();
        assert!(error.message().contains("not allowed"), "{sql}: {error}");
    }
}

/// None of the default functions can change the role. p14g does not refuse any function a policy adds, see
/// `DANGEROUS_FUNCTIONS.md`.
#[test]
fn no_default_function_changes_the_role() {
    for name in functions::defaults() {
        assert!(!common::changes_role(name), "{name} is a default");
    }
}

/// `assert_cannot_change_role` finds a call wherever it is, including the places `ParseResult::functions()` misses.
#[test]
fn every_call_is_seen() {
    for sql in [
        "SELECT set_config('role', 'none', false)",
        "SELECT * FROM set_config('role', 'none', false)",
        "INSERT INTO t (a) VALUES (set_config('role', 'none', false))",
        "INSERT INTO t (a) VALUES (1), (set_config('role', 'none', false))",
        "INSERT INTO t (a) VALUES (1) RETURNING set_config('role', 'none', false)",
        "SELECT * FROM (VALUES (set_config('role', 'none', false))) v",
        "SELECT count(*) FILTER (WHERE set_config('role', 'none', false) = 'x') FROM t",
        "SELECT string_agg(a, ',' ORDER BY set_config('role', 'none', false)) FROM t",
        "SELECT count(*) OVER (PARTITION BY set_config('role', 'none', false)) FROM t",
        "SELECT count(*) OVER (ORDER BY set_config('role', 'none', false)) FROM t",
        "SELECT a FROM t LIMIT length(set_config('role', 'none', false))",
        "SELECT a FROM t OFFSET length(set_config('role', 'none', false))",
        "SELECT ARRAY[set_config('role', 'none', false)]",
        "SELECT a FROM t ORDER BY set_config('role', 'none', false) COLLATE \"C\"",
        "SELECT \"pg_catalog\".\"set_config\"('role', 'none', false)",
        "SELECT query_to_xml('select 1', true, true, '')",
        "SELECT * FROM public.dblink('', 'select 1') AS d (x int)",
        // a column reference Postgres reads as a call when the table has no such column
        "SELECT t.reset_role FROM t",
        "SELECT a FROM t ORDER BY t.reset_role",
    ] {
        let caught = panic::catch_unwind(|| assert_cannot_change_role(sql, "test"));
        assert!(caught.is_err(), "not caught: {sql}");
    }
    // and only those
    assert_cannot_change_role("SELECT lower(a), count(*) OVER (ORDER BY b) FROM t LIMIT 3", "test");
}
