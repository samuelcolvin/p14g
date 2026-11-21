//! The policy and case files shared by the test suites.
#![allow(dead_code, reason = "each test binary uses a different part of this module")]

use pgsafe::{Delete, ErrorKind, Insert, Literals, Op, Policy, PolicyBuilder, Select, Update};

/// The policy the case files are written against. `cases/schema.sql` grants a database role the same
/// access, so Postgres can be used to check pgsafe's answers.
pub fn builder() -> PolicyBuilder {
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
        .select(Select::table("cheap_orders"))
        // a table with an inheritance child the policy must not reach
        .select(Select::table("family").columns(["id", "label"]).only(true))
        .insert(Insert::table("family").columns(["id", "label"]))
        .update(Update::table("family").columns(["label"]).only(true))
        .delete(Delete::table("family").only(true))
        .insert(
            Insert::table("orders")
                .columns(["product", "qty"])
                .extra(|()| [("tenant_id", 42)]),
        )
        .insert(
            Insert::table("audit")
                .columns(["message"])
                .extra(|()| [("tenant_id", 42)]),
        )
        .insert(Insert::table("cheap_orders"))
        .update(Update::table("orders").columns(["qty"]))
        .update(Update::table("cheap_orders").columns(["qty"]))
        .delete(Delete::table("orders"))
        .delete(Delete::table("cheap_orders"))
}

pub fn policy() -> Policy {
    builder().build().unwrap()
}

pub fn params_policy() -> Policy {
    builder().literals(Literals::Params).build().unwrap()
}

/// An accepted statement, and the exact SQL it must be rewritten to when the case file gives it.
pub struct Accept {
    pub line: usize,
    pub sql: &'static str,
    pub expected: Option<&'static str>,
}

/// Cases are separated by blank lines: the SQL, then optionally `=> ` and the expected output.
pub fn accept_cases() -> Vec<Accept> {
    let mut cases = Vec::new();
    let mut lines = include_str!("../cases/accept.sql").lines().enumerate().peekable();
    while let Some((index, line)) = lines.next() {
        if line.trim().is_empty() || line.starts_with("--") {
            continue;
        }
        let expected = lines
            .next_if(|(_, next)| next.starts_with("=> "))
            .map(|(_, next)| &next[3..]);
        cases.push(Accept {
            line: index + 1,
            sql: line,
            expected,
        });
    }
    cases
}

pub struct Reject {
    pub line: usize,
    pub kind: ErrorKind,
    pub sql: &'static str,
}

/// One case per line: the error kind, a colon, the SQL.
pub fn reject_cases() -> Vec<Reject> {
    include_str!("../cases/reject.sql")
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.starts_with("--"))
        .map(|(index, line)| {
            let (kind, sql) = line
                .split_once(": ")
                .unwrap_or_else(|| panic!("line {}: no kind", index + 1));
            let kind = match kind {
                "parse" => ErrorKind::Parse,
                "unsupported" => ErrorKind::Unsupported,
                "denied" => ErrorKind::Denied,
                "limit" => ErrorKind::Limit,
                other => panic!("line {}: unknown kind {other:?}", index + 1),
            };
            Reject {
                line: index + 1,
                kind,
                sql,
            }
        })
        .collect()
}
