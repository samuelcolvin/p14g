//! Rule filters: a condition the policy adds to every statement that uses a table.
//!
//! A filter is an SQL expression written by the policy author, with values bound to its placeholders. It
//! is parsed and lowered like any other SQL, so it reaches the output through the same writer and no part
//! of it, or of a value, is pasted in as text. It is not checked against the policy: it is trusted, and it
//! usually names a column the untrusted SQL may not.

use std::collections::BTreeSet;

use crate::{
    ast::{BinaryOperator, Expr, Ident},
    error::{Error, Result},
    lower,
    policy::{Filter, Limits},
};

/// A filter ready to go into a statement.
pub(crate) struct Bound {
    pub expr: Expr,
    /// The columns of the table the condition reads.
    pub columns: BTreeSet<Ident>,
}

/// Parse `filter` and bind its columns to one table instance.
///
/// `table` is the name the rule gave the table and `qualifier` is the name its columns go by in the
/// statement: the alias if it has one. The filter may write a column bare or as `table.column`.
pub(crate) fn bind(filter: &Filter, table: &Ident, qualifier: &Ident, limits: &Limits) -> Result<Bound> {
    // without the position, which is one in the filter's text and would read as one in the statement
    let invalid = |e: Error| Error::callback(format!("invalid filter for table {table:?}: {}", e.message()));
    let (expr, columns) =
        lower::parse_filter(&filter.sql, limits, &filter.values, table, qualifier).map_err(invalid)?;
    Ok(Bound { expr, columns })
}

/// `filters AND (selection)`, the `WHERE` of a write with the rule's filters applied.
pub(crate) fn and(filters: Vec<Expr>, selection: Option<Expr>) -> Option<Expr> {
    filters.into_iter().chain(selection).reduce(|left, right| Expr::Binary {
        left: Box::new(left),
        op: BinaryOperator::And,
        right: Box::new(right),
    })
}
