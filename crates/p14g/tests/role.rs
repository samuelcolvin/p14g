//! Nothing p14g accepts may change, reset or get around the role its output runs as.
//!
//! This is the restriction everything else rests on: the grants and row-level security the caller set up
//! apply to a role, and a statement that can leave that role has neither. The cases are in `cases/role.sql`;
//! `postgres.rs` also checks, after every accepted statement, that the role and settings are unchanged.

mod common;

use common::{assert_cannot_change_role, builder, policy, role_cases};
use p14g::{Dialect, Literals, Policy, Select, Update};

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

/// A policy cannot allow `set_config`, or an `UPDATE` of `pg_settings`, which calls it.
#[test]
fn policy_cannot_allow_changing_the_role() {
    for function in ["set_config", "pg_catalog.set_config"] {
        let error = Policy::<()>::builder().functions([function]).build().err().unwrap();
        assert!(error.message().contains("set_config"), "{function}: {error}");
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

    // a function of that name in another schema is another function
    let policy: Policy = Policy::builder()
        .select(Select::table("orders").columns(["id"]))
        .functions(["app.set_config"])
        .build()
        .unwrap();
    assert!(policy.rewrite("select app.set_config(id) from orders", &()).is_ok());
    assert!(policy.rewrite("select set_config('role', 'none', false)", &()).is_err());
    assert!(
        policy
            .rewrite("select pg_catalog.set_config('role', 'none', false)", &())
            .is_err()
    );

    // and so is a table of that name in another schema
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
