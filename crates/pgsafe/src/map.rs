//! Mappers: trusted callbacks that rewrite parts of a statement after it has passed the policy.
//!
//! A mapper sees one node and returns its replacement. What it returns is not checked against the policy
//! again, which is the point: it is how `events` becomes `tenant_42.events`. It still goes through the
//! same writer as everything else, so a mapper can change what is queried but cannot inject SQL text.

use std::mem;

use crate::{
    ast::{
        Column, Delete, Expr, Function, FunctionArgs, Insert, Literal, OrderBy, Query, Select, SelectItem, SetExpr,
        Statement, Table, TableFactor, Update,
    },
    error::Result,
};

/// Rewrites nodes of a checked statement. Every method defaults to leaving the node alone.
///
/// Nodes are visited bottom-up, so a function's arguments have already been mapped when the function is.
/// Mappers run in the order they were added and each is given what the one before returned. The inside of
/// a replacement is not visited.
pub trait Mapper<C>: Send + Sync {
    /// A table or view in `FROM`, or the target of a write.
    ///
    /// If the name changes and no alias is set, pgsafe keeps the original name as the alias so that the
    /// statement's column references still resolve.
    fn map_table(&self, table: Table, context: &C) -> Result<Table> {
        let _ = context;
        Ok(table)
    }

    fn map_column(&self, column: Column, context: &C) -> Result<Expr> {
        let _ = context;
        Ok(Expr::Column(column))
    }

    fn map_function(&self, function: Function, context: &C) -> Result<Expr> {
        let _ = context;
        Ok(Expr::Function(function))
    }

    fn map_literal(&self, literal: Literal, context: &C) -> Result<Expr> {
        let _ = context;
        Ok(Expr::Literal(literal))
    }
}

/// The mappers behind `PolicyBuilder::map_table` and friends: a closure for one kind of node.
pub(crate) struct TableMapper<F>(pub F);

impl<C, F: Fn(Table, &C) -> Result<Table> + Send + Sync> Mapper<C> for TableMapper<F> {
    fn map_table(&self, table: Table, context: &C) -> Result<Table> {
        (self.0)(table, context)
    }
}

pub(crate) struct ColumnMapper<F>(pub F);

impl<C, F: Fn(Column, &C) -> Result<Expr> + Send + Sync> Mapper<C> for ColumnMapper<F> {
    fn map_column(&self, column: Column, context: &C) -> Result<Expr> {
        (self.0)(column, context)
    }
}

pub(crate) struct FunctionMapper<F>(pub F);

impl<C, F: Fn(Function, &C) -> Result<Expr> + Send + Sync> Mapper<C> for FunctionMapper<F> {
    fn map_function(&self, function: Function, context: &C) -> Result<Expr> {
        (self.0)(function, context)
    }
}

pub(crate) struct LiteralMapper<F>(pub F);

impl<C, F: Fn(Literal, &C) -> Result<Expr> + Send + Sync> Mapper<C> for LiteralMapper<F> {
    fn map_literal(&self, literal: Literal, context: &C) -> Result<Expr> {
        (self.0)(literal, context)
    }
}

pub(crate) fn apply<C>(mappers: &[Box<dyn Mapper<C>>], statement: &mut Statement, context: &C) -> Result<()> {
    if mappers.is_empty() {
        return Ok(());
    }
    let walker = Walker { mappers, context };
    match statement {
        Statement::Query(query) => walker.query(query),
        Statement::Insert(Insert {
            table,
            columns: _,
            rows,
            returning,
        }) => {
            walker.table(table)?;
            for row in rows {
                walker.exprs(row)?;
            }
            walker.select_items(returning)
        }
        Statement::Update(Update {
            table,
            assignments,
            selection,
            returning,
        }) => {
            walker.table(table)?;
            for assignment in assignments {
                walker.expr(&mut assignment.value)?;
            }
            walker.optional(selection.as_mut())?;
            walker.select_items(returning)
        }
        Statement::Delete(Delete {
            table,
            selection,
            returning,
        }) => {
            walker.table(table)?;
            walker.optional(selection.as_mut())?;
            walker.select_items(returning)
        }
    }
}

struct Walker<'a, C> {
    mappers: &'a [Box<dyn Mapper<C>>],
    context: &'a C,
}

impl<C> Walker<'_, C> {
    fn table(&self, table: &mut Table) -> Result<()> {
        let original = table.clone();
        let mut mapped = original.clone();
        for mapper in self.mappers {
            mapped = mapper.map_table(mapped, self.context)?;
        }
        let renamed = mapped.schema != original.schema || mapped.name != original.name;
        if renamed && mapped.alias.is_none() {
            // columns were qualified with the original name before the mapper ran
            mapped.alias = Some(original.name);
        }
        *table = mapped;
        Ok(())
    }

    fn query(&self, query: &mut Query) -> Result<()> {
        let Query {
            with,
            body,
            order_by,
            limit,
            offset,
        } = query;
        for cte in with {
            self.query(&mut cte.query)?;
        }
        self.set_expr(body)?;
        self.order_by(order_by)?;
        self.optional(limit.as_mut())?;
        self.optional(offset.as_mut())
    }

    fn set_expr(&self, body: &mut SetExpr) -> Result<()> {
        match body {
            SetExpr::Select(select) => self.select(select),
            SetExpr::Query(query) => self.query(query),
            SetExpr::SetOperation {
                op: _,
                all: _,
                left,
                right,
            } => {
                self.set_expr(left)?;
                self.set_expr(right)
            }
        }
    }

    fn select(&self, select: &mut Select) -> Result<()> {
        let Select {
            distinct: _,
            projection,
            from,
            selection,
            group_by,
            having,
        } = select;
        for table in from {
            self.factor(&mut table.relation)?;
            for join in &mut table.joins {
                self.factor(&mut join.relation)?;
                self.optional(join.on.as_mut())?;
            }
        }
        self.select_items(projection)?;
        self.optional(selection.as_mut())?;
        self.exprs(group_by)?;
        self.optional(having.as_mut())
    }

    fn factor(&self, factor: &mut TableFactor) -> Result<()> {
        match factor {
            TableFactor::Table(table) => self.table(table),
            TableFactor::Derived { subquery, alias: _ } => self.query(subquery),
        }
    }

    fn select_items(&self, items: &mut [SelectItem]) -> Result<()> {
        for item in items {
            if let SelectItem::Expr { expr, alias: _ } = item {
                self.expr(expr)?;
            }
        }
        Ok(())
    }

    fn order_by(&self, order_by: &mut [OrderBy]) -> Result<()> {
        order_by.iter_mut().try_for_each(|item| self.expr(&mut item.expr))
    }

    fn exprs(&self, exprs: &mut [Expr]) -> Result<()> {
        exprs.iter_mut().try_for_each(|expr| self.expr(expr))
    }

    fn optional(&self, expr: Option<&mut Expr>) -> Result<()> {
        expr.map_or(Ok(()), |expr| self.expr(expr))
    }

    fn expr(&self, expr: &mut Expr) -> Result<()> {
        self.children(expr)?;
        // each mapper sees the node only while it is still the kind of node that mapper handles
        for mapper in self.mappers {
            let node = mem::replace(expr, Expr::Literal(Literal::Null));
            *expr = match node {
                Expr::Column(column) => mapper.map_column(column, self.context)?,
                Expr::Function(function) => mapper.map_function(function, self.context)?,
                Expr::Literal(literal) => mapper.map_literal(literal, self.context)?,
                other => {
                    *expr = other;
                    break;
                }
            };
        }
        Ok(())
    }

    fn children(&self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Column(_) | Expr::Literal(_) | Expr::Placeholder(_) | Expr::OutputColumn(_) | Expr::Ordinal(_) => {
                Ok(())
            }
            Expr::Unary { op: _, expr }
            | Expr::Is {
                expr,
                test: _,
                negated: _,
            }
            | Expr::Cast { expr, data_type: _ }
            | Expr::Extract { field: _, expr } => self.expr(expr),
            Expr::Binary { left, op: _, right }
            | Expr::IsDistinctFrom {
                left,
                right,
                negated: _,
            } => {
                self.expr(left)?;
                self.expr(right)
            }
            Expr::InList { expr, list, negated: _ } => {
                self.expr(expr)?;
                self.exprs(list)
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated: _,
            } => {
                self.expr(expr)?;
                self.query(subquery)
            }
            Expr::Between {
                expr,
                low,
                high,
                negated: _,
            } => {
                self.expr(expr)?;
                self.expr(low)?;
                self.expr(high)
            }
            Expr::Like {
                kind: _,
                expr,
                pattern,
                escape,
                negated: _,
            } => {
                self.expr(expr)?;
                self.expr(pattern)?;
                self.optional(escape.as_deref_mut())
            }
            Expr::Case {
                operand,
                branches,
                else_result,
            } => {
                self.optional(operand.as_deref_mut())?;
                for (condition, result) in branches {
                    self.expr(condition)?;
                    self.expr(result)?;
                }
                self.optional(else_result.as_deref_mut())
            }
            Expr::Function(Function {
                schema: _,
                name: _,
                args,
                distinct: _,
                order_by,
                filter,
                over,
            }) => {
                match args {
                    FunctionArgs::Niladic | FunctionArgs::Star => {}
                    FunctionArgs::List(args) => self.exprs(args)?,
                }
                self.order_by(order_by)?;
                self.optional(filter.as_deref_mut())?;
                if let Some(window) = over {
                    self.exprs(&mut window.partition_by)?;
                    self.order_by(&mut window.order_by)?;
                }
                Ok(())
            }
            Expr::Exists { subquery, negated: _ } | Expr::Subquery(subquery) => self.query(subquery),
        }
    }
}
