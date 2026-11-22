//! Check p14g's output with Postgres's own parser (via libpg_query), with no database needed.
//!
//! p14g reads SQL with sqlparser, which is not Postgres. So for everything p14g emits, ask the real
//! parser what it sees: it must parse, and the tables and functions it finds must be ones the policy allows.

mod common;

use std::collections::BTreeSet;

use common::{accept_cases, builder, params_policy, policy};
use p14g::functions;

const TABLES: &[&str] = &[
    "family",
    "orders",
    "customers",
    "v",
    "app.events",
    "limited",
    "cheap_orders",
    "audit",
];

fn assert_within_policy(sql: &str, line: usize) {
    common::assert_cannot_change_role(sql, &format!("line {line}"));
    let parsed = pg_query::parse(sql).unwrap_or_else(|e| panic!("line {line}: Postgres cannot parse {sql}\n  {e}"));

    let cte_names: BTreeSet<String> = parsed.cte_names.iter().cloned().collect();
    for table in parsed.tables() {
        assert!(
            TABLES.contains(&table.as_str()) || cte_names.contains(&table),
            "line {line}: Postgres sees table {table:?} in {sql}"
        );
    }
    for function in common::called_functions(&parsed) {
        // builtins are written by name unless the policy sets `qualify_builtins`; the grammar qualifies the
        // ones it produces itself, `btrim` for `TRIM` and `like_escape` for `LIKE ... ESCAPE`
        let name = function.strip_prefix("pg_catalog.").unwrap_or(&function);
        assert!(
            functions::is_default(name) || name == "btrim" || name == "like_escape",
            "line {line}: Postgres sees function {function:?} in {sql}"
        );
    }
}

#[test]
fn postgres_parser_agrees() {
    let inline = policy();
    let params = params_policy();
    // the `LIMIT` that `max_rows` adds must leave every statement one that Postgres accepts
    let capped = builder().max_rows(Some(10)).build().unwrap();
    for case in accept_cases() {
        assert_within_policy(&inline.rewrite(case.sql, &()).unwrap().sql, case.line);
        assert_within_policy(&params.rewrite(case.sql, &()).unwrap().sql, case.line);
        assert_within_policy(&capped.rewrite(case.sql, &()).unwrap().sql, case.line);
    }
}

/// The queries the policy rejects really would have reached something forbidden: if Postgres's parser
/// sees no forbidden table or function in any of them, the case file is not testing what it claims to.
#[test]
fn rejected_cases_name_forbidden_things() {
    let forbidden = common::reject_cases()
        .iter()
        .filter_map(|case| pg_query::parse(case.sql).ok())
        .filter(|parsed| {
            parsed.tables().iter().any(|t| !TABLES.contains(&t.as_str()))
                || common::called_functions(parsed)
                    .iter()
                    .any(|f| !functions::is_default(f))
        })
        .count();
    assert!(
        forbidden > 50,
        "only {forbidden} rejected cases name a forbidden table or function"
    );
}
