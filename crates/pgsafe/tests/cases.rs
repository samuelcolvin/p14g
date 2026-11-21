//! The case files: what the test policy accepts, exactly what it is rewritten to, and what it rejects.

mod common;

use common::{accept_cases, params_policy, policy, reject_cases};

#[test]
fn accepted() {
    let policy = policy();
    let mut failures = Vec::new();
    for case in accept_cases() {
        match policy.check(case.sql, &()) {
            Ok(safe) => {
                if let Some(expected) = case.expected
                    && safe.sql != expected
                {
                    failures.push(format!(
                        "line {}: {}\n  expected: {expected}\n  got:      {}",
                        case.line, case.sql, safe.sql
                    ));
                }
                assert!(
                    safe.params.is_empty(),
                    "line {}: inline mode returned params",
                    case.line
                );
            }
            Err(e) => failures.push(format!("line {}: {}\n  rejected: {e}", case.line, case.sql)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn rejected() {
    let policy = policy();
    let mut failures = Vec::new();
    for case in reject_cases() {
        match policy.check(case.sql, &()) {
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

/// The output of pgsafe is itself SQL pgsafe accepts, and checking it again changes nothing. If the
/// writer and the parser ever disagreed about what a piece of output means, this is where it would show.
#[test]
fn idempotent() {
    let policy = common::builder()
        // the output of an insert already has the policy's extra column in it
        .insert(pgsafe::Insert::table("orders").columns(["product", "qty", "tenant_id"]))
        .insert(pgsafe::Insert::table("audit").columns(["message", "tenant_id"]))
        .build()
        .unwrap();
    let first_policy = common::policy();
    for case in accept_cases() {
        let first = first_policy.check(case.sql, &()).unwrap();
        let second = policy
            .check(&first.sql, &())
            .unwrap_or_else(|e| panic!("line {}: output was rejected: {e}\n  {}", case.line, first.sql));
        assert_eq!(first.sql, second.sql, "line {}", case.line);
        assert_eq!(first.kind, second.kind, "line {}", case.line);
        assert_eq!(first.tables, second.tables, "line {}", case.line);
    }
}

/// With `Literals::Params` no string from the input reaches the SQL text.
#[test]
fn params_mode_has_no_string_literals() {
    let policy = params_policy();
    for case in accept_cases() {
        let safe = policy.check(case.sql, &()).unwrap();
        assert!(!safe.sql.contains('\''), "line {}: {}", case.line, safe.sql);
    }
}
