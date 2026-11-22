//! Nothing p14g accepts may change, reset or get around the role its output runs as.
//!
//! This is the restriction everything else rests on: the grants and row-level security the caller set up
//! apply to a role, and a statement that can leave that role has neither. The cases are in `cases/role.sql`;
//! `postgres.rs` also checks, after every accepted statement, that the role and settings are unchanged.

mod common;

use std::panic;

use common::{assert_cannot_change_role, builder, policy, role_cases};
use p14g::{Dialect, Filter, Literals, Policy, Select, Update, functions};

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
            builder().dialect(dialect).qualify_builtins(true).build().unwrap(),
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

/// A policy cannot allow a function that can change the role, in any schema or in a filter, or an `UPDATE` of
/// `pg_settings`, which calls `set_config`.
#[test]
fn policy_cannot_allow_changing_the_role() {
    for name in functions::FORBIDDEN {
        for function in [
            (*name).to_owned(),
            format!("pg_catalog.{name}"),
            format!("public.{name}"),
        ] {
            let error = Policy::<()>::builder()
                .functions([function.as_str()])
                .build()
                .err()
                .unwrap_or_else(|| panic!("{function} was allowed"));
            assert!(error.message().contains("change the role"), "{function}: {error}");
        }
    }
    let error = Policy::<()>::builder()
        .default_functions(false)
        .functions(["set_config"])
        .build()
        .err()
        .unwrap();
    assert!(error.message().contains("set_config"), "{error}");

    for table in ["pg_settings", "pg_catalog.pg_settings"] {
        let error = Policy::<()>::builder()
            .update(Update::table(table).columns(["setting"]))
            .build()
            .err()
            .unwrap();
        assert!(error.message().contains("pg_settings"), "{table}: {error}");
    }
    // a table of that name in another schema is another table
    Policy::<()>::builder()
        .update(Update::table("app.pg_settings").columns(["setting"]))
        .build()
        .unwrap();
    Policy::<()>::builder()
        .default_schema("app")
        .update(Update::table("pg_settings").columns(["setting"]))
        .build()
        .unwrap();
}

/// A filter is trusted, but it cannot change the role either.
#[test]
fn filter_cannot_change_the_role() {
    for condition in [
        "set_config('role', 'none', false) is not null",
        "pg_catalog.set_config('role', 'none', false) is not null",
        "org = 1 and query_to_xml('select 1', true, true, '') is not null",
        "length(ts_stat('select 1')::text) > 0",
    ] {
        let policy: Policy = Policy::builder()
            .select(
                Select::table("orders")
                    .columns(["id"])
                    .filter(move |()| Filter::new(condition)),
            )
            .build()
            .unwrap();
        let error = policy.rewrite("select id from orders", &()).unwrap_err();
        assert!(error.message().contains("change the role"), "{condition}: {error}");
    }
}

/// `called_functions` finds a call wherever it is, including the places `ParseResult::functions()` misses.
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
    ] {
        let caught = panic::catch_unwind(|| assert_cannot_change_role(sql, "test"));
        assert!(caught.is_err(), "not caught: {sql}");
    }
    // and only those
    assert_cannot_change_role("SELECT lower(a), count(*) OVER (ORDER BY b) FROM t LIMIT 3", "test");
}
