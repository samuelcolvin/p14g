//! Rule filters: a condition the policy adds to every statement that uses a table.
//!
//! A filter is an SQL expression written by the policy author, with values bound to its placeholders. It
//! is parsed and lowered like any other SQL, so it reaches the output through the same writer and no part
//! of it, or of a value, is pasted in as text. It is not checked against the policy: like a mapper it is
//! trusted, and it usually names a column the untrusted SQL may not.

use std::{collections::BTreeSet, sync::Mutex};

use crate::{
    ast::{BinaryOperator, Column, Expr, Ident},
    error::{Error, Result},
    lower,
    map::{self, Mapper},
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
    let mut expr = lower::parse_filter(&filter.sql, limits, &filter.values).map_err(invalid)?;
    let qualify = Qualify {
        table,
        qualifier,
        columns: Mutex::new(BTreeSet::new()),
    };
    map::apply_to_expr(&qualify, &mut expr).map_err(invalid)?;
    let columns = qualify
        .columns
        .into_inner()
        .expect("nothing panics while holding the lock");
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

/// Qualifies every column of a filter with the table instance it belongs to, and records which were used.
struct Qualify<'a> {
    table: &'a Ident,
    qualifier: &'a Ident,
    columns: Mutex<BTreeSet<Ident>>,
}

impl Mapper<()> for Qualify<'_> {
    fn map_column(&self, mut column: Column, (): &()) -> Result<Expr> {
        if let Some(named) = &column.table
            && named != self.table
            && named != self.qualifier
        {
            return Err(Error::callback(format!(
                "{named}.{} is a column of another table",
                column.name
            )));
        }
        column.table = Some(self.qualifier.clone());
        self.columns
            .lock()
            .expect("nothing panics while holding the lock")
            .insert(column.name.clone());
        Ok(Expr::Column(column))
    }
}
