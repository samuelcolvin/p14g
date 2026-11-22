//! The policy and case files shared by the test suites.
#![allow(dead_code, reason = "each test binary uses a different part of this module")]

use p14g::{Delete, ErrorKind, Insert, Layout, Literals, Policy, PolicyBuilder, Select, Update};

/// The policy the case files are written against. `cases/schema.sql` grants a database role the same
/// access, so Postgres can be used to check p14g's answers.
pub fn builder() -> PolicyBuilder {
    Policy::builder()
        // one statement per line, as the case files need
        .layout(Layout::Dense)
        .select(Select::table("orders", ["id", "product", "qty", "customer_id"]))
        .select(Select::table("customers", ["id", "name"]))
        .select(Select::table(
            "v",
            ["id", "product", "qty", "created", "data", "tags", "a\"b", "MiXed"],
        ))
        .select(Select::table("app.events", ["id", "kind"]))
        .select(Select::table("limited", ["a", "b"]))
        .select(Select::table("cheap_orders", ["id", "product", "qty"]))
        // a table with an inheritance child the policy must not reach
        .select(Select::table("family", ["id", "label"]).only(true))
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
    parse_rejects(include_str!("../cases/reject.sql"))
}

/// Statements that would change or get around the role the output runs as, in the format of `reject.sql`.
pub fn role_cases() -> Vec<Reject> {
    parse_rejects(include_str!("../cases/role.sql"))
}

fn parse_rejects(file: &'static str) -> Vec<Reject> {
    file.lines()
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

/// Functions the output checks look for: each can change the role a statement runs as, by setting `role` or by
/// running SQL given as text. `reset_role` is the function `cases/schema.sql` defines for every table's row, which
/// Postgres would call for a column reference `t.reset_role`.
///
/// This is for tests only, and not exhaustive: `DANGEROUS_FUNCTIONS.md` has more, and p14g itself refuses
/// every function its policy does not allow, rather than these.
pub const ROLE_CHANGING: &[&str] = &[
    "set_config",
    "query_to_xml",
    "query_to_xml_and_xmlschema",
    "ts_stat",
    "ts_rewrite",
    "dblink",
    "dblink_exec",
    "dblink_open",
    "dblink_send_query",
    "reset_role",
];

/// Whether the last part of `name` is in [`ROLE_CHANGING`].
pub fn changes_role(name: &str) -> bool {
    name.rsplit('.')
        .next()
        .is_some_and(|name| ROLE_CHANGING.contains(&name))
}

/// Every column reference in `parsed`, by its last name: Postgres reads `t.name` as the call `name(t)` when `t`
/// has no column `name`.
pub fn column_names(parsed: &pg_query::ParseResult) -> Vec<String> {
    fn walk(value: &Value, names: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(column) = map.get("ColumnRef")
                    && let Some(name) = column["fields"]
                        .as_array()
                        .and_then(|fields| fields.last())
                        .and_then(|field| field.pointer("/node/String/sval"))
                        .and_then(Value::as_str)
                {
                    names.push(name.to_owned());
                }
                map.values().for_each(|value| walk(value, names));
            }
            Value::Array(values) => values.iter().for_each(|value| walk(value, names)),
            _ => {}
        }
    }

    use serde_json::Value;

    let tree = serde_json::to_value(&parsed.protobuf).expect("a parse tree serializes");
    let mut names = Vec::new();
    walk(&tree, &mut names);
    names
}

/// Every function call in `parsed`, as `schema.name` or `name`, wherever it is in the statement.
///
/// `ParseResult::functions()` and `nodes()` miss calls in `VALUES`, `RETURNING`, `FILTER`, `OVER`, `LIMIT`,
/// `ARRAY[...]` and under `COLLATE`, so this serializes the whole tree and looks at every node.
/// `crates/fuzz/src/lib.rs` has the same function.
pub fn called_functions(parsed: &pg_query::ParseResult) -> Vec<String> {
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

    use serde_json::Value;

    let tree = serde_json::to_value(&parsed.protobuf).expect("a parse tree serializes");
    let mut calls = Vec::new();
    walk(&tree, &mut calls);
    calls
}

/// Panic unless Postgres's own parser reads `sql` as one `SELECT`, `INSERT`, `UPDATE` or `DELETE` that calls none
/// of [`ROLE_CHANGING`], directly or as a column reference, and names no `pg_settings`: a statement that cannot
/// change the role it runs as, provided its tables are what the test schema says.
///
/// Every other kind of statement is a utility statement or `MERGE`, and none of those can appear inside these
/// four in Postgres's grammar. `crates/fuzz/src/lib.rs` makes the same check.
pub fn assert_cannot_change_role(sql: &str, context: &str) {
    use pg_query::NodeEnum;

    let parsed = pg_query::parse(sql).unwrap_or_else(|e| panic!("{context}: Postgres cannot parse {sql}\n  {e}"));
    assert_eq!(parsed.protobuf.stmts.len(), 1, "{context}: not one statement: {sql}");
    let node = parsed.protobuf.stmts[0]
        .stmt
        .as_ref()
        .and_then(|stmt| stmt.node.as_ref());
    assert!(
        matches!(
            node,
            Some(NodeEnum::SelectStmt(_) | NodeEnum::InsertStmt(_) | NodeEnum::UpdateStmt(_) | NodeEnum::DeleteStmt(_))
        ),
        "{context}: not a SELECT, INSERT, UPDATE or DELETE: {sql}"
    );
    for function in called_functions(&parsed) {
        assert!(!changes_role(&function), "{context}: calls {function}: {sql}");
    }
    for column in column_names(&parsed) {
        assert!(
            !changes_role(&column),
            "{context}: reads {column}, which can be a call: {sql}"
        );
    }
    for table in parsed.tables() {
        assert!(
            table.rsplit('.').next() != Some("pg_settings"),
            "{context}: names {table}: {sql}"
        );
    }
}
