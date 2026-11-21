use sqlparser::ast as sp;

use super::{Lower, ident, qualified_name, reject, single_name};
use crate::{
    ast::{
        Cte, Expr, Ident, Join, JoinKind, KeyExpr, Literal, OrderBy, Query, Select, SelectItem, SetExpr, SetOperator,
        SortExpr, Table, TableFactor, TableWithJoins,
    },
    error::{Error, Result},
};

impl Lower<'_> {
    pub(super) fn query(&mut self, query: sp::Query) -> Result<Query> {
        self.nested(|this| this.query_inner(query))
    }

    fn query_inner(&mut self, query: sp::Query) -> Result<Query> {
        self.node()?;
        let sp::Query {
            with,
            body,
            order_by,
            limit_clause,
            fetch,
            locks,
            for_clause,
            settings,
            format_clause,
            pipe_operators,
        } = query;
        reject(&fetch, "FETCH")?;
        reject(&locks, "FOR UPDATE / FOR SHARE")?;
        reject(&for_clause, "a FOR clause")?;
        reject(&settings, "SETTINGS")?;
        reject(&format_clause, "FORMAT")?;
        reject(&pipe_operators, "pipe operators")?;

        let with = match with {
            None => Vec::new(),
            Some(sp::With {
                with_token: _,
                recursive,
                cte_tables,
            }) => {
                reject(&recursive, "WITH RECURSIVE")?;
                cte_tables.into_iter().map(|cte| self.cte(cte)).collect::<Result<_>>()?
            }
        };
        let body = self.set_expr(*body)?;
        let order_by = match order_by {
            None => Vec::new(),
            Some(sp::OrderBy { kind, interpolate }) => {
                reject(&interpolate, "INTERPOLATE")?;
                match kind {
                    sp::OrderByKind::Expressions(exprs) => {
                        exprs.into_iter().map(|e| self.order_by(e)).collect::<Result<_>>()?
                    }
                    sp::OrderByKind::All(_) => return Err(Error::unsupported("ORDER BY ALL")),
                }
            }
        };
        let (limit, offset) = match limit_clause {
            None => (None, None),
            Some(sp::LimitClause::LimitOffset {
                limit,
                offset,
                limit_by,
            }) => {
                reject(&limit_by, "LIMIT BY")?;
                let limit = limit.map(|e| self.limit_value(e, "LIMIT")).transpose()?;
                let offset = offset
                    .map(|sp::Offset { value, rows: _ }| self.limit_value(value, "OFFSET"))
                    .transpose()?;
                (limit, offset)
            }
            Some(sp::LimitClause::OffsetCommaLimit { .. }) => return Err(Error::unsupported("LIMIT offset, limit")),
        };
        Ok(Query {
            with,
            body,
            order_by,
            limit,
            offset,
        })
    }

    /// `LIMIT` and `OFFSET` take a number or a placeholder, nothing that needs resolving.
    fn limit_value(&mut self, expr: sp::Expr, what: &str) -> Result<Expr> {
        match self.expr(expr)? {
            value @ (Expr::Literal(Literal::Number(_)) | Expr::Placeholder(_)) => Ok(value),
            _ => Err(Error::unsupported(format!(
                "{what} that is not a number or a placeholder"
            ))),
        }
    }

    fn cte(&mut self, cte: sp::Cte) -> Result<Cte> {
        let sp::Cte {
            alias,
            query,
            from,
            materialized,
            closing_paren_token: _,
        } = cte;
        reject(&from, "a CTE with FROM")?;
        reject(&materialized, "MATERIALIZED")?;
        let sp::TableAlias {
            explicit: _,
            name,
            columns,
            at,
        } = alias;
        reject(&columns, "a column list on a CTE")?;
        reject(&at, "AT on a CTE")?;
        self.count_subquery()?;
        Ok(Cte {
            name: ident(name)?,
            query: self.query(*query)?,
        })
    }

    fn set_expr(&mut self, body: sp::SetExpr) -> Result<SetExpr> {
        self.nested(|this| this.set_expr_inner(body))
    }

    fn set_expr_inner(&mut self, body: sp::SetExpr) -> Result<SetExpr> {
        match body {
            sp::SetExpr::Select(select) => Ok(SetExpr::Select(Box::new(self.select(*select)?))),
            sp::SetExpr::Query(query) => {
                self.count_subquery()?;
                Ok(SetExpr::Query(Box::new(self.query(*query)?)))
            }
            sp::SetExpr::SetOperation {
                left,
                op,
                set_quantifier,
                right,
            } => {
                self.set_operations += 1;
                if self.set_operations > self.limits.max_set_operations {
                    return Err(Error::limit(format!(
                        "SQL has more than {} set operations",
                        self.limits.max_set_operations
                    )));
                }
                let op = match op {
                    sp::SetOperator::Union => SetOperator::Union,
                    sp::SetOperator::Except => SetOperator::Except,
                    sp::SetOperator::Intersect => SetOperator::Intersect,
                    sp::SetOperator::Minus => return Err(Error::unsupported("MINUS")),
                };
                let all = match set_quantifier {
                    sp::SetQuantifier::All => true,
                    sp::SetQuantifier::Distinct | sp::SetQuantifier::None => false,
                    sp::SetQuantifier::ByName | sp::SetQuantifier::AllByName | sp::SetQuantifier::DistinctByName => {
                        return Err(Error::unsupported("BY NAME"));
                    }
                };
                Ok(SetExpr::SetOperation {
                    op,
                    all,
                    left: Box::new(self.set_expr(*left)?),
                    right: Box::new(self.set_expr(*right)?),
                })
            }
            sp::SetExpr::Values(_) => Err(Error::unsupported("VALUES as a query")),
            sp::SetExpr::Insert(_) | sp::SetExpr::Update(_) | sp::SetExpr::Delete(_) | sp::SetExpr::Merge(_) => {
                Err(Error::unsupported("a data-modifying statement inside a query"))
            }
            sp::SetExpr::Table(_) => Err(Error::unsupported("TABLE")),
        }
    }

    fn select(&mut self, select: sp::Select) -> Result<Select> {
        self.node()?;
        let sp::Select {
            select_token: _,
            optimizer_hints,
            distinct,
            select_modifiers,
            top,
            top_before_distinct: _,
            projection,
            exclude,
            into,
            from,
            lateral_views,
            prewhere,
            selection,
            connect_by,
            group_by,
            cluster_by,
            distribute_by,
            sort_by,
            having,
            named_window,
            qualify,
            window_before_qualify: _,
            value_table_mode,
            flavor,
        } = select;
        reject(&optimizer_hints, "an optimizer hint")?;
        reject(&select_modifiers, "a SELECT modifier")?;
        reject(&top, "TOP")?;
        reject(&exclude, "EXCLUDE")?;
        reject(&into, "SELECT INTO")?;
        reject(&lateral_views, "LATERAL VIEW")?;
        reject(&prewhere, "PREWHERE")?;
        reject(&connect_by, "CONNECT BY")?;
        reject(&cluster_by, "CLUSTER BY")?;
        reject(&distribute_by, "DISTRIBUTE BY")?;
        reject(&sort_by, "SORT BY")?;
        reject(&named_window, "a WINDOW clause")?;
        reject(&qualify, "QUALIFY")?;
        reject(&value_table_mode, "SELECT AS VALUE / STRUCT")?;
        if !matches!(flavor, sp::SelectFlavor::Standard) {
            return Err(Error::unsupported("FROM before SELECT"));
        }
        let distinct = match distinct {
            None | Some(sp::Distinct::All) => false,
            Some(sp::Distinct::Distinct) => true,
            Some(sp::Distinct::On(_)) => return Err(Error::unsupported("DISTINCT ON")),
        };
        if projection.is_empty() {
            return Err(Error::unsupported("an empty select list"));
        }
        if projection.len() > self.limits.max_projection {
            return Err(Error::limit(format!(
                "select list has more than {} items",
                self.limits.max_projection
            )));
        }
        let projection = self.select_items(projection)?;
        let from = from
            .into_iter()
            .enumerate()
            .map(|(index, table)| {
                if index > 0 {
                    self.count_join()?;
                }
                self.table_with_joins(table)
            })
            .collect::<Result<_>>()?;
        let selection = selection.map(|e| self.expr(e)).transpose()?;
        let group_by = match group_by {
            sp::GroupByExpr::Expressions(exprs, modifiers) => {
                reject(&modifiers, "a GROUP BY modifier")?;
                exprs
                    .into_iter()
                    .map(|e| self.expr(e).map(KeyExpr::Expr))
                    .collect::<Result<_>>()?
            }
            sp::GroupByExpr::All(_) => return Err(Error::unsupported("GROUP BY ALL")),
        };
        let having = having.map(|e| self.expr(e)).transpose()?;
        Ok(Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
        })
    }

    /// Lower a select list, also used for `RETURNING`.
    pub(super) fn select_items(&mut self, items: Vec<sp::SelectItem>) -> Result<Vec<SelectItem>> {
        items.into_iter().map(|item| self.select_item(item)).collect()
    }

    fn select_item(&mut self, item: sp::SelectItem) -> Result<SelectItem> {
        match item {
            sp::SelectItem::UnnamedExpr(expr) => Ok(SelectItem::Expr {
                expr: self.expr(expr)?,
                alias: None,
            }),
            sp::SelectItem::ExprWithAlias { expr, alias } => Ok(SelectItem::Expr {
                expr: self.expr(expr)?,
                alias: Some(ident(alias)?),
            }),
            sp::SelectItem::ExprWithAliases { .. } => Err(Error::unsupported("several aliases for one expression")),
            sp::SelectItem::Wildcard(options) => {
                wildcard_options(options)?;
                Ok(SelectItem::Wildcard)
            }
            sp::SelectItem::QualifiedWildcard(kind, options) => {
                wildcard_options(options)?;
                match kind {
                    sp::SelectItemQualifiedWildcardKind::ObjectName(name) => Ok(SelectItem::QualifiedWildcard(
                        single_name(name, "a qualified wildcard")?,
                    )),
                    sp::SelectItemQualifiedWildcardKind::Expr(_) => {
                        Err(Error::unsupported("a wildcard on an expression"))
                    }
                }
            }
        }
    }

    fn count_join(&mut self) -> Result<()> {
        self.joins += 1;
        if self.joins > self.limits.max_joins {
            Err(Error::limit(format!(
                "SQL has more than {} joins",
                self.limits.max_joins
            )))
        } else {
            Ok(())
        }
    }

    pub(super) fn table_with_joins(&mut self, table: sp::TableWithJoins) -> Result<TableWithJoins> {
        let sp::TableWithJoins { relation, joins } = table;
        Ok(TableWithJoins {
            relation: self.table_factor(relation)?,
            joins: joins.into_iter().map(|j| self.join(j)).collect::<Result<_>>()?,
        })
    }

    fn join(&mut self, join: sp::Join) -> Result<Join> {
        self.count_join()?;
        let sp::Join {
            relation,
            global,
            join_operator,
        } = join;
        reject(&global, "GLOBAL JOIN")?;
        let (kind, constraint) = match join_operator {
            sp::JoinOperator::Join(c) | sp::JoinOperator::Inner(c) => (JoinKind::Inner, c),
            sp::JoinOperator::Left(c) | sp::JoinOperator::LeftOuter(c) => (JoinKind::Left, c),
            sp::JoinOperator::Right(c) | sp::JoinOperator::RightOuter(c) => (JoinKind::Right, c),
            sp::JoinOperator::FullOuter(c) => (JoinKind::Full, c),
            sp::JoinOperator::CrossJoin(c) => (JoinKind::Cross, c),
            _ => return Err(Error::unsupported("this kind of join")),
        };
        let on = match (kind, constraint) {
            (JoinKind::Cross, sp::JoinConstraint::None) => None,
            (JoinKind::Cross, _) => return Err(Error::unsupported("CROSS JOIN with a condition")),
            (_, sp::JoinConstraint::On(expr)) => Some(self.expr(expr)?),
            (_, sp::JoinConstraint::Using(_) | sp::JoinConstraint::UsingAlias(..)) => {
                return Err(Error::unsupported("JOIN ... USING (write the condition with ON)"));
            }
            (_, sp::JoinConstraint::Natural) => return Err(Error::unsupported("NATURAL JOIN")),
            (_, sp::JoinConstraint::None) => return Err(Error::unsupported("a join without ON")),
        };
        Ok(Join {
            kind,
            relation: self.table_factor(relation)?,
            on,
        })
    }

    fn table_factor(&mut self, factor: sp::TableFactor) -> Result<TableFactor> {
        self.node()?;
        match factor {
            sp::TableFactor::Table {
                name,
                alias,
                args,
                with_hints,
                version,
                with_ordinality,
                partitions,
                json_path,
                sample,
                index_directives,
                inheritance,
            } => {
                reject(&args, "a table function")?;
                reject(&with_hints, "a table hint")?;
                reject(&version, "a table version")?;
                reject(&with_ordinality, "WITH ORDINALITY")?;
                reject(&partitions, "PARTITION")?;
                reject(&json_path, "a JSON path on a table")?;
                reject(&sample, "TABLESAMPLE")?;
                reject(&index_directives, "an index hint")?;
                let only = match inheritance {
                    None => false,
                    Some(sp::TableInheritance::Only { parenthesized: _ }) => true,
                    Some(sp::TableInheritance::IncludeDescendants) => {
                        return Err(Error::unsupported("* after a table name"));
                    }
                };
                Ok(TableFactor::Table(Table {
                    only,
                    ..table(name, alias)?
                }))
            }
            sp::TableFactor::Derived {
                lateral,
                subquery,
                alias,
                sample,
            } => {
                reject(&lateral, "LATERAL")?;
                reject(&sample, "TABLESAMPLE")?;
                let Some(alias) = alias else {
                    return Err(Error::unsupported("a subquery in FROM without an alias"));
                };
                self.count_subquery()?;
                Ok(TableFactor::Derived {
                    subquery: Box::new(self.query(*subquery)?),
                    alias: table_alias(alias)?,
                })
            }
            _ => Err(Error::unsupported("this kind of FROM item")),
        }
    }

    fn order_by(&mut self, order_by: sp::OrderByExpr) -> Result<OrderBy> {
        let SortExpr {
            expr,
            descending,
            nulls_first,
        } = self.sort_expr(order_by)?;
        // whether this is a position, an output column or an expression is decided once the select list is known
        Ok(OrderBy {
            key: KeyExpr::Expr(expr),
            descending,
            nulls_first,
        })
    }

    fn sort_expr(&mut self, order_by: sp::OrderByExpr) -> Result<SortExpr> {
        let sp::OrderByExpr {
            expr,
            options: sp::OrderByOptions { sort, nulls_first },
            with_fill,
        } = order_by;
        reject(&with_fill, "WITH FILL")?;
        let descending = match sort {
            None => None,
            Some(sp::OrderBySort::Asc) => Some(false),
            Some(sp::OrderBySort::Desc) => Some(true),
            Some(sp::OrderBySort::Using(_)) => return Err(Error::unsupported("ORDER BY ... USING")),
        };
        Ok(SortExpr {
            expr: self.expr(expr)?,
            descending,
            nulls_first,
        })
    }

    /// Lower the `ORDER BY` of an aggregate call or a window.
    pub(super) fn sort_exprs(&mut self, order_by: Vec<sp::OrderByExpr>) -> Result<Vec<SortExpr>> {
        order_by.into_iter().map(|o| self.sort_expr(o)).collect()
    }
}

fn wildcard_options(options: sp::WildcardAdditionalOptions) -> Result<()> {
    let sp::WildcardAdditionalOptions {
        wildcard_token: _,
        opt_ilike,
        opt_exclude,
        opt_except,
        opt_replace,
        opt_rename,
        opt_alias,
    } = options;
    reject(&opt_ilike, "* ILIKE")?;
    reject(&opt_exclude, "* EXCLUDE")?;
    reject(&opt_except, "* EXCEPT")?;
    reject(&opt_replace, "* REPLACE")?;
    reject(&opt_rename, "* RENAME")?;
    reject(&opt_alias, "an alias on *")
}

fn table_alias(alias: sp::TableAlias) -> Result<Ident> {
    let sp::TableAlias {
        explicit: _,
        name,
        columns,
        at,
    } = alias;
    reject(&columns, "a column list on a table alias")?;
    reject(&at, "AT on a table alias")?;
    ident(name)
}

/// Lower a table name and optional alias, for `FROM` and for the target of a write.
pub(super) fn table(name: sp::ObjectName, alias: Option<sp::TableAlias>) -> Result<Table> {
    let (schema, name) = qualified_name(name, "a table name")?;
    Ok(Table {
        schema,
        name,
        alias: alias.map(table_alias).transpose()?,
        only: false,
    })
}
