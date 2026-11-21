//! Resolve every column to the table it belongs to and check the statement against the policy.
//!
//! p14g never sees the database, so the policy doubles as the schema: a table has the columns its rules
//! list, or an unknown set of columns when a rule allows all of them. Every column reference is bound to
//! one table instance here and written fully qualified, so if Postgres would have resolved a name
//! differently the query fails in the database instead of reading something that was not checked.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ast::{
        BinaryOperator, Column, Delete, Expr, Function, FunctionArgs, Ident, Insert, KeyExpr, LikeKind, Literal,
        OrderBy, Query, Select, SelectItem, SetExpr, Statement, Table, TableFactor, UnaryOperator, Update,
    },
    error::{Error, Result},
    policy::{Op, OpSet, Policy, SelectRule, Star, TableKey, function_lookup_key},
};

/// Check `statement` against `policy`, rewriting it in place: columns are qualified, `*` is expanded and
/// insert `extra` columns are added. Returns the sorted names of the tables used.
pub(crate) fn check<C>(policy: &Policy<C>, statement: &mut Statement, context: &C) -> Result<Vec<String>> {
    let mut checker = Checker {
        policy,
        instances: Vec::new(),
        scopes: Vec::new(),
        ctes: Vec::new(),
        tables: BTreeSet::new(),
    };
    match statement {
        Statement::Query(query) => {
            checker.query(query, true)?;
        }
        Statement::Insert(insert) => checker.insert(insert, context)?,
        Statement::Update(update) => checker.update(update)?,
        Statement::Delete(delete) => checker.delete(delete)?,
    }
    checker.finish()?;
    Ok(checker.tables.into_iter().collect())
}

/// Add a `LIMIT` to a `SELECT` that has none, and lower one that is above `max_rows`.
pub(crate) fn apply_max_rows(statement: &mut Statement, max_rows: u64) -> Result<()> {
    let Statement::Query(query) = statement else {
        return Ok(());
    };
    let cap = || Some(Expr::Literal(Literal::Number(max_rows.to_string())));
    match &query.limit {
        None => query.limit = cap(),
        Some(Expr::Literal(Literal::Number(number))) => {
            // anything that is not a plain integer no bigger than the cap is replaced by the cap
            if number.parse::<u64>().map_or(true, |n| n > max_rows) {
                query.limit = cap();
            }
        }
        Some(_) => {
            return Err(Error::denied("LIMIT must be a number when the policy sets max_rows"));
        }
    }
    Ok(())
}

/// Indexes into `Checker::instances`.
type Refs = BTreeSet<usize>;

/// One table, view, subquery or CTE in a `FROM` clause, or the target of a write.
struct Instance<'p> {
    /// The name its columns are qualified with.
    alias: Ident,
    kind: InstanceKind<'p>,
    used_columns: BTreeSet<Ident>,
    used_operators: OpSet,
    /// The rule chosen for a base table once its scope is complete.
    rule: Option<&'p SelectRule>,
}

enum InstanceKind<'p> {
    Base {
        name: String,
        /// The select rules for the table. Empty for the target of a write that has no select rule, which
        /// can then be written to but not read from.
        rules: &'p [SelectRule],
    },
    Derived {
        columns: Vec<Ident>,
        /// The subquery has a `*` that was left unexpanded, so it has columns p14g does not know about.
        open: bool,
    },
}

impl Instance<'_> {
    /// Whether the instance is known to have this column.
    fn lists(&self, column: &Ident) -> bool {
        match &self.kind {
            InstanceKind::Base { rules, .. } => rules
                .iter()
                .any(|rule| rule.columns.as_ref().is_some_and(|columns| columns.contains(column))),
            InstanceKind::Derived { columns, .. } => columns.contains(column),
        }
    }

    /// Whether the instance may have columns p14g does not know about.
    fn open(&self) -> bool {
        match &self.kind {
            InstanceKind::Base { rules, .. } => rules.iter().any(|rule| rule.columns.is_none()),
            InstanceKind::Derived { open, .. } => *open,
        }
    }
}

struct Scope {
    instances: Vec<usize>,
    /// Scopes below this one are not visible: set for derived tables and CTEs, which cannot be correlated.
    barrier: bool,
}

/// What a query produces, as seen by an enclosing query.
struct Outputs {
    /// One per output column, `None` where the column has no usable name.
    names: Vec<Option<Ident>>,
    /// The query has an unexpanded `*`, so there are more columns than `names`.
    open: bool,
}

impl Outputs {
    fn named(&self) -> Vec<Ident> {
        self.names.iter().flatten().cloned().collect()
    }
}

struct Checker<'p, C> {
    policy: &'p Policy<C>,
    instances: Vec<Instance<'p>>,
    scopes: Vec<Scope>,
    /// CTEs in scope, innermost `WITH` last.
    ctes: Vec<BTreeMap<Ident, (Vec<Ident>, bool)>>,
    tables: BTreeSet<String>,
}

fn table_key(table: &Table) -> TableKey {
    TableKey {
        schema: table.schema.clone(),
        name: table.name.clone(),
    }
}

impl<'p, C> Checker<'p, C> {
    /// Operators recorded against a table after its rule was chosen (from an enclosing query) still have
    /// to be allowed by that rule.
    fn finish(&self) -> Result<()> {
        for instance in &self.instances {
            if let (Some(rule), InstanceKind::Base { name, .. }) = (instance.rule, &instance.kind) {
                operators_allowed(instance.used_operators, rule.operators, Some(name))?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- queries

    fn query(&mut self, query: &mut Query, barrier: bool) -> Result<(Outputs, Refs)> {
        let mut refs = Refs::new();
        self.ctes.push(BTreeMap::new());
        let result = self.query_inner(query, barrier, &mut refs);
        self.ctes.pop();
        result.map(|outputs| (outputs, refs))
    }

    fn query_inner(&mut self, query: &mut Query, barrier: bool, refs: &mut Refs) -> Result<Outputs> {
        for cte in &mut query.with {
            let (outputs, cte_refs) = self.query(&mut cte.query, true)?;
            refs.extend(cte_refs);
            let frame = self.ctes.last_mut().expect("query pushed a CTE frame");
            if frame
                .insert(cte.name.clone(), (outputs.named(), outputs.open))
                .is_some()
            {
                return Err(Error::denied(format!("CTE name {:?} is used more than once", cte.name)));
            }
        }
        let Query {
            with: _,
            body,
            order_by,
            limit: _,
            offset: _,
        } = query;
        self.set_expr(body, order_by, barrier, refs)
    }

    /// Check a query body. `order_by` is the `ORDER BY` that applies to this body directly.
    fn set_expr(
        &mut self,
        body: &mut SetExpr,
        order_by: &mut [OrderBy],
        barrier: bool,
        refs: &mut Refs,
    ) -> Result<Outputs> {
        match body {
            SetExpr::Select(select) => self.select(select, order_by, barrier, refs),
            SetExpr::Query(inner) => {
                let (outputs, inner_refs) = self.query(inner, barrier)?;
                refs.extend(inner_refs);
                Self::order_by_outputs(order_by, &outputs)?;
                Ok(outputs)
            }
            SetExpr::SetOperation {
                op: _,
                all: _,
                left,
                right,
            } => {
                let outputs = self.set_expr(left, &mut [], barrier, refs)?;
                self.set_expr(right, &mut [], barrier, refs)?;
                Self::order_by_outputs(order_by, &outputs)?;
                Ok(outputs)
            }
        }
    }

    /// `ORDER BY` on a set operation or a parenthesised query can only name output columns.
    fn order_by_outputs(order_by: &mut [OrderBy], outputs: &Outputs) -> Result<()> {
        for item in order_by {
            match &item.key {
                KeyExpr::Expr(Expr::Column(Column { table: None, name }))
                    if outputs.names.iter().flatten().any(|n| n == name) =>
                {
                    item.key = KeyExpr::Output(name.clone());
                }
                KeyExpr::Expr(Expr::Literal(Literal::Number(number))) if !outputs.open => {
                    item.key = KeyExpr::Position(ordinal(number, outputs.names.len())?);
                }
                _ => {
                    return Err(Error::denied(
                        "ORDER BY on a combined query must name one of its output columns",
                    ));
                }
            }
        }
        Ok(())
    }

    fn select(
        &mut self,
        select: &mut Select,
        order_by: &mut [OrderBy],
        barrier: bool,
        refs: &mut Refs,
    ) -> Result<Outputs> {
        self.scopes.push(Scope {
            instances: Vec::new(),
            barrier,
        });
        let result = self.select_inner(select, order_by, refs);
        self.scopes.pop();
        result
    }

    fn select_inner(&mut self, select: &mut Select, order_by: &mut [OrderBy], refs: &mut Refs) -> Result<Outputs> {
        let Select {
            distinct: _,
            projection,
            from,
            selection,
            group_by,
            having,
        } = select;

        // every FROM item is added before any join condition is looked at, so a condition can name any of
        // them. Postgres is stricter about which are visible where, and will say so.
        let mut conditions = Vec::new();
        for table in from.iter_mut() {
            self.add_factor(&mut table.relation, refs)?;
            for join in &mut table.joins {
                self.add_factor(&mut join.relation, refs)?;
                conditions.extend(join.on.as_mut());
            }
        }
        for condition in conditions {
            self.expr(condition, refs)?;
        }
        if let Some(selection) = selection {
            self.expr(selection, refs)?;
        }

        let has_wildcard = projection.iter().any(|item| !matches!(item, SelectItem::Expr { .. }));
        let aliases: Vec<(usize, Ident)> = projection
            .iter()
            .enumerate()
            .filter_map(|(index, item)| match item {
                SelectItem::Expr { alias: Some(alias), .. } => Some((index, alias.clone())),
                _ => None,
            })
            .collect();

        for item in projection.iter_mut() {
            if let SelectItem::Expr { expr, alias: _ } = item {
                self.expr(expr, refs)?;
            }
        }
        for key in group_by.iter_mut() {
            self.group_by(key, &aliases, projection.len(), has_wildcard, refs)?;
        }
        if let Some(having) = having {
            self.expr(having, refs)?;
        }
        for item in order_by.iter_mut() {
            match &mut item.key {
                // a bare name that matches an output alias: Postgres always picks the output column in
                // ORDER BY, so writing it bare is unambiguous
                KeyExpr::Expr(Expr::Column(Column { table: None, name }))
                    if aliases.iter().any(|(_, alias)| alias == name) =>
                {
                    item.key = KeyExpr::Output(name.clone());
                }
                KeyExpr::Expr(Expr::Literal(Literal::Number(number))) => {
                    item.key = KeyExpr::Position(checked_ordinal(number, projection.len(), has_wildcard)?);
                }
                KeyExpr::Expr(expr) => self.expr(expr, refs)?,
                KeyExpr::Position(_) | KeyExpr::Output(_) => {}
            }
        }
        self.close_scope(projection)
    }

    /// `GROUP BY name` prefers an input column, and falls back to an output alias. p14g cannot always
    /// tell which Postgres will pick, so it only accepts the cases where it can, or where both are allowed.
    fn group_by(
        &mut self,
        key: &mut KeyExpr,
        aliases: &[(usize, Ident)],
        columns: usize,
        has_wildcard: bool,
        refs: &mut Refs,
    ) -> Result<()> {
        let expr = match key {
            KeyExpr::Position(_) | KeyExpr::Output(_) => return Ok(()),
            KeyExpr::Expr(Expr::Literal(Literal::Number(number))) => {
                *key = KeyExpr::Position(checked_ordinal(number, columns, has_wildcard)?);
                return Ok(());
            }
            KeyExpr::Expr(expr) => expr,
        };
        let Expr::Column(Column { table: None, name }) = &*expr else {
            return self.expr(expr, refs);
        };
        let Some((index, _)) = aliases.iter().find(|(_, alias)| alias == name) else {
            return self.expr(expr, refs);
        };
        let scope = self.scopes.last().expect("select pushed a scope");
        let listed = scope.instances.iter().any(|&i| self.instances[i].lists(name));
        if listed {
            // a real input column of that name wins in Postgres too
            return self.expr(expr, refs);
        }
        let any_open = scope.instances.iter().any(|&i| self.instances[i].open());
        if scope.instances.iter().all(|&i| self.instances[i].open_base_only()) {
            // Postgres only looks at this query level for an input column of that name, and every
            // column of every table at this level is allowed, so the bare name is safe either way
            *key = KeyExpr::Output(name.clone());
            Ok(())
        } else if !any_open && !has_wildcard {
            // no visible table is known to have the column, so it must be the alias: say so by position
            let position = u32::try_from(index + 1).expect("projection length is limited");
            *key = KeyExpr::Position(position);
            Ok(())
        } else {
            Err(Error::denied(format!(
                "GROUP BY {name:?} could be a column or the output alias, repeat the expression instead"
            )))
        }
    }

    /// Finish the innermost scope: choose a rule for each table, then expand `*`.
    fn close_scope(&mut self, projection: &mut Vec<SelectItem>) -> Result<Outputs> {
        let scope_instances = self.scopes.last().expect("select pushed a scope").instances.clone();
        for &index in &scope_instances {
            self.choose_rule(index)?;
        }
        self.expand_projection(projection, &scope_instances)
    }

    fn choose_rule(&mut self, index: usize) -> Result<()> {
        let instance = &mut self.instances[index];
        let InstanceKind::Base { name, rules } = &instance.kind else {
            return Ok(());
        };
        if rules.is_empty() {
            // a write-only target: any read of it was already refused
            return Ok(());
        }
        let columns_fit = |rule: &SelectRule| {
            rule.columns
                .as_ref()
                .is_none_or(|columns| instance.used_columns.iter().all(|c| columns.contains(c)))
        };
        let rule = rules
            .iter()
            .find(|rule| columns_fit(rule) && rule.operators.contains_all(instance.used_operators));
        if let Some(rule) = rule {
            instance.rule = Some(rule);
            Ok(())
        } else {
            // say which half failed: with one rule, or when the columns fit some rule, it is the operators
            if let Some(rule) = rules.iter().find(|rule| columns_fit(rule)) {
                operators_allowed(instance.used_operators, rule.operators, Some(name))?;
            }
            Err(Error::denied(format!(
                "no single rule for table {name:?} allows these columns together: {}",
                instance
                    .used_columns
                    .iter()
                    .map(Ident::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }

    /// Apply the star behaviour to a select list or `RETURNING`, and work out the output columns.
    fn expand_projection(&mut self, projection: &mut Vec<SelectItem>, scope_instances: &[usize]) -> Result<Outputs> {
        let mut outputs = Outputs {
            names: Vec::new(),
            open: false,
        };
        let mut expanded = Vec::with_capacity(projection.len());
        for item in projection.drain(..) {
            let targets: Vec<usize> = match &item {
                SelectItem::Expr { expr, alias } => {
                    outputs.names.push(alias.clone().or_else(|| match expr {
                        Expr::Column(column) => Some(column.name.clone()),
                        _ => None,
                    }));
                    expanded.push(item);
                    continue;
                }
                SelectItem::Wildcard => {
                    if scope_instances.is_empty() {
                        return Err(Error::denied("* needs a FROM clause"));
                    }
                    scope_instances.to_vec()
                }
                SelectItem::QualifiedWildcard(alias) => {
                    let index = scope_instances
                        .iter()
                        .copied()
                        .find(|&i| &self.instances[i].alias == alias)
                        .ok_or_else(|| Error::denied(format!("{alias}.* does not name a table in this FROM clause")))?;
                    vec![index]
                }
            };
            match self.policy.star {
                Star::Reject => return Err(Error::denied("* is not allowed, list the columns")),
                Star::Allow => {
                    for &index in &targets {
                        if self.star_columns(index)?.is_some() {
                            return Err(Error::denied(format!(
                                "* is not allowed on {:?} because only some of its columns are allowed, list the columns",
                                self.instances[index].alias
                            )));
                        }
                    }
                    outputs.open = true;
                    expanded.push(item);
                }
                Star::Expand => {
                    for &index in &targets {
                        let alias = self.instances[index].alias.clone();
                        if let Some(columns) = self.star_columns(index)? {
                            for name in columns {
                                self.instances[index].used_columns.insert(name.clone());
                                outputs.names.push(Some(name.clone()));
                                expanded.push(SelectItem::Expr {
                                    expr: Expr::Column(Column {
                                        table: Some(alias.clone()),
                                        name,
                                    }),
                                    alias: None,
                                });
                            }
                        } else {
                            outputs.open = true;
                            expanded.push(SelectItem::QualifiedWildcard(alias));
                        }
                    }
                }
            }
        }
        *projection = expanded;
        Ok(outputs)
    }

    /// The columns `*` stands for on an instance, or `None` when it has to stay a `*`.
    fn star_columns(&self, index: usize) -> Result<Option<Vec<Ident>>> {
        let instance = &self.instances[index];
        match &instance.kind {
            InstanceKind::Derived { open: true, .. } => Ok(None),
            InstanceKind::Derived { columns, open: false } => Ok(Some(columns.clone())),
            InstanceKind::Base { name, rules } => {
                if let Some(rule) = instance.rule {
                    Ok(rule.columns.clone())
                } else {
                    debug_assert!(rules.is_empty());
                    Err(Error::denied(format!("reading from table {name:?} is not allowed")))
                }
            }
        }
    }

    fn add_instance(&mut self, alias: Ident, kind: InstanceKind<'p>) -> Result<usize> {
        let scope = self.scopes.last().expect("a scope is open");
        if scope.instances.iter().any(|&i| self.instances[i].alias == alias) {
            return Err(Error::denied(format!(
                "table name {alias:?} is used more than once, give one of them an alias"
            )));
        }
        let index = self.instances.len();
        self.instances.push(Instance {
            alias,
            kind,
            used_columns: BTreeSet::new(),
            used_operators: OpSet::default(),
            rule: None,
        });
        self.scopes.last_mut().expect("a scope is open").instances.push(index);
        Ok(index)
    }

    fn add_factor(&mut self, factor: &mut TableFactor, refs: &mut Refs) -> Result<()> {
        let index = match factor {
            TableFactor::Table(table) => {
                let cte = if table.schema.is_none() {
                    self.ctes.iter().rev().find_map(|frame| frame.get(&table.name)).cloned()
                } else {
                    None
                };
                let alias = table.reference_name().clone();
                if let Some((columns, open)) = cte {
                    if table.only {
                        return Err(Error::denied(format!(
                            "ONLY cannot be used on the CTE {:?}",
                            table.name
                        )));
                    }
                    self.add_instance(alias, InstanceKind::Derived { columns, open })?
                } else {
                    self.qualify(table);
                    let name = table.qualified_name();
                    let rules = self
                        .policy
                        .selects
                        .get(&table_key(table))
                        .ok_or_else(|| Error::denied(format!("reading from table {name:?} is not allowed")))?;
                    // the statement may ask for ONLY itself, the policy can only add it
                    table.only |= self.policy.only.contains(&table_key(table));
                    self.tables.insert(name.clone());
                    self.add_instance(alias, InstanceKind::Base { name, rules })?
                }
            }
            TableFactor::Derived { subquery, alias } => {
                let (outputs, inner_refs) = self.query(subquery, true)?;
                refs.extend(inner_refs);
                self.add_instance(
                    alias.clone(),
                    InstanceKind::Derived {
                        columns: outputs.named(),
                        open: outputs.open,
                    },
                )?
            }
        };
        refs.insert(index);
        Ok(())
    }

    // ---------------------------------------------------------------- expressions

    /// Bind a column reference to an instance, record the use, and qualify it.
    fn column(&mut self, column: &mut Column, refs: &mut Refs) -> Result<()> {
        let index = self.resolve(column)?;
        let instance = &mut self.instances[index];
        instance.used_columns.insert(column.name.clone());
        column.table = Some(instance.alias.clone());
        refs.insert(index);
        Ok(())
    }

    fn resolve(&self, column: &Column) -> Result<usize> {
        let name = &column.name;
        let mut hidden = false;
        for scope in self.scopes.iter().rev() {
            if hidden {
                break;
            }
            hidden = scope.barrier;
            if let Some(table) = &column.table {
                let Some(&index) = scope.instances.iter().find(|&&i| &self.instances[i].alias == table) else {
                    continue;
                };
                let instance = &self.instances[index];
                return if instance.lists(name) || instance.open() {
                    Ok(index)
                } else {
                    Err(Error::denied(format!("column {table}.{name} is not allowed")))
                };
            }
            let listed: Vec<usize> = scope
                .instances
                .iter()
                .copied()
                .filter(|&i| self.instances[i].lists(name))
                .collect();
            match listed.as_slice() {
                [index] => return Ok(*index),
                [] => {}
                _ => {
                    return Err(Error::denied(format!(
                        "column {name:?} is ambiguous, qualify it with a table name"
                    )));
                }
            }
            let open: Vec<usize> = scope
                .instances
                .iter()
                .copied()
                .filter(|&i| self.instances[i].open())
                .collect();
            match open.as_slice() {
                [index] => return Ok(*index),
                [] => {}
                _ => {
                    return Err(Error::denied(format!(
                        "column {name:?} could belong to more than one table, qualify it with a table name"
                    )));
                }
            }
        }
        Err(match &column.table {
            Some(table) => Error::denied(format!("{table}.{name}: there is no table {table:?} here")),
            None => Error::denied(format!("column {name:?} is not allowed")),
        })
    }

    /// Record that `op` is applied to an expression that reads the instances in `refs`.
    fn operator(&mut self, op: Op, refs: &Refs) -> Result<()> {
        if refs.is_empty() {
            let mut used = OpSet::default();
            used.insert(op);
            return operators_allowed(used, self.policy.default_operators, None);
        }
        for &index in refs {
            self.instances[index].used_operators.insert(op);
        }
        Ok(())
    }

    fn expr(&mut self, expr: &mut Expr, refs: &mut Refs) -> Result<()> {
        // `inner` collects what this expression reads, so an operator is charged to exactly those tables
        let mut inner = Refs::new();
        let op = self.expr_inner(expr, &mut inner)?;
        if let Some(op) = op {
            self.operator(op, &inner)?;
        }
        refs.extend(inner);
        Ok(())
    }

    fn exprs<'e>(&mut self, exprs: impl IntoIterator<Item = &'e mut Expr>, refs: &mut Refs) -> Result<()> {
        exprs.into_iter().try_for_each(|expr| self.expr(expr, refs))
    }

    fn subquery(&mut self, query: &mut Query, refs: &mut Refs) -> Result<()> {
        let (_, inner) = self.query(query, false)?;
        refs.extend(inner);
        Ok(())
    }

    /// Check the children of `expr`, and return the operator the expression itself applies, if any.
    fn expr_inner(&mut self, expr: &mut Expr, refs: &mut Refs) -> Result<Option<Op>> {
        match expr {
            Expr::Column(column) => {
                self.column(column, refs)?;
                Ok(None)
            }
            Expr::Literal(_) | Expr::Placeholder(_) => Ok(None),
            Expr::Unary { op, expr } => {
                self.expr(expr, refs)?;
                Ok(Some(match op {
                    UnaryOperator::Not => Op::Not,
                    UnaryOperator::Minus => Op::Minus,
                    UnaryOperator::Plus => Op::Plus,
                }))
            }
            Expr::Binary { left, op, right } => {
                self.expr(left, refs)?;
                self.expr(right, refs)?;
                Ok(Some(binary_op(*op)))
            }
            Expr::Is {
                expr,
                test: _,
                negated: _,
            } => {
                self.expr(expr, refs)?;
                Ok(Some(Op::Is))
            }
            Expr::IsDistinctFrom {
                left,
                right,
                negated: _,
            } => {
                self.expr(left, refs)?;
                self.expr(right, refs)?;
                Ok(Some(Op::IsDistinctFrom))
            }
            Expr::InList { expr, list, negated: _ } => {
                self.expr(expr, refs)?;
                self.exprs(list, refs)?;
                Ok(Some(Op::In))
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated: _,
            } => {
                self.expr(expr, refs)?;
                self.subquery(subquery, refs)?;
                Ok(Some(Op::In))
            }
            Expr::Between {
                expr,
                low,
                high,
                negated: _,
            } => {
                self.expr(expr, refs)?;
                self.expr(low, refs)?;
                self.expr(high, refs)?;
                Ok(Some(Op::Between))
            }
            Expr::Like {
                kind,
                expr,
                pattern,
                escape,
                negated: _,
            } => {
                self.expr(expr, refs)?;
                self.expr(pattern, refs)?;
                if let Some(escape) = escape {
                    self.expr(escape, refs)?;
                }
                Ok(Some(match kind {
                    LikeKind::Like => Op::Like,
                    LikeKind::ILike => Op::ILike,
                    LikeKind::SimilarTo => Op::SimilarTo,
                }))
            }
            Expr::Case {
                operand,
                branches,
                else_result,
            } => {
                if let Some(operand) = operand {
                    self.expr(operand, refs)?;
                }
                for (condition, result) in branches {
                    self.expr(condition, refs)?;
                    self.expr(result, refs)?;
                }
                if let Some(else_result) = else_result {
                    self.expr(else_result, refs)?;
                }
                Ok(None)
            }
            Expr::Cast { expr, data_type: _ } => {
                self.expr(expr, refs)?;
                Ok(None)
            }
            Expr::Extract { field: _, expr } => {
                self.function_allowed(None, "extract")?;
                self.expr(expr, refs)?;
                Ok(None)
            }
            Expr::Function(function) => {
                self.function(function, refs)?;
                Ok(None)
            }
            // the keyword forms are allowed and denied under their names, like any other function
            Expr::Variadic { function, first, rest } => {
                self.function_allowed(None, function.name())?;
                self.expr(first, refs)?;
                self.exprs(rest, refs)?;
                Ok(None)
            }
            Expr::NullIf { left, right } => {
                self.function_allowed(None, "nullif")?;
                self.expr(left, refs)?;
                self.expr(right, refs)?;
                Ok(None)
            }
            Expr::CurrentDate => self.function_allowed(None, "current_date").map(|()| None),
            Expr::CurrentTimestamp => self.function_allowed(None, "current_timestamp").map(|()| None),
            Expr::Trim {
                side: _,
                expr,
                characters,
            } => {
                self.function_allowed(None, "trim")?;
                self.expr(expr, refs)?;
                if let Some(characters) = characters {
                    self.expr(characters, refs)?;
                }
                Ok(None)
            }
            Expr::Exists { subquery, negated: _ } | Expr::Subquery(subquery) => {
                self.subquery(subquery, refs)?;
                Ok(None)
            }
        }
    }

    fn function_allowed(&self, schema: Option<&Ident>, name: &str) -> Result<()> {
        let key = match schema {
            Some(schema) if schema.as_str() != "pg_catalog" => format!("{schema}.{name}"),
            _ => name.to_owned(),
        };
        if self.policy.functions.contains(&key) {
            Ok(())
        } else {
            Err(Error::denied(format!("function {key:?} is not allowed")))
        }
    }

    fn function(&mut self, function: &mut Function, refs: &mut Refs) -> Result<()> {
        let Function {
            schema,
            name,
            args,
            filter,
            over,
        } = function;
        debug_assert_eq!(
            function_lookup_key(schema.as_ref(), name).contains('.'),
            schema.as_ref().is_some_and(|s| s.as_str() != "pg_catalog")
        );
        self.function_allowed(schema.as_ref(), name.as_str())?;
        match args {
            FunctionArgs::Star => {}
            FunctionArgs::List {
                args,
                distinct: _,
                order_by,
            } => {
                self.exprs(args, refs)?;
                self.exprs(order_by.iter_mut().map(|o| &mut o.expr), refs)?;
            }
        }
        if let Some(filter) = filter {
            self.expr(filter, refs)?;
        }
        if let Some(window) = over {
            self.exprs(&mut window.partition_by, refs)?;
            self.exprs(window.order_by.iter_mut().map(|o| &mut o.expr), refs)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- writes

    /// Open a scope holding just the target of a write, so `WHERE`, `SET` and `RETURNING` can read it as
    /// far as the table's select rules allow.
    /// Give an unqualified table the policy's default schema, so that it is looked up and written with it.
    fn qualify(&self, table: &mut Table) {
        if table.schema.is_none() {
            table.schema.clone_from(&self.policy.default_schema);
        }
    }

    fn write_scope(&mut self, table: &mut Table, takes_only: bool) -> Result<usize> {
        if takes_only {
            table.only |= self.policy.only.contains(&table_key(table));
        }
        let name = table.qualified_name();
        let rules = self
            .policy
            .selects
            .get(&table_key(table))
            .map_or(&[][..], Vec::as_slice);
        self.tables.insert(name.clone());
        self.scopes.push(Scope {
            instances: Vec::new(),
            barrier: true,
        });
        self.add_instance(table.reference_name().clone(), InstanceKind::Base { name, rules })
    }

    /// Close the scope of a write, checking and expanding `RETURNING` on the way.
    fn close_write_scope(&mut self, returning: &mut Vec<SelectItem>) -> Result<()> {
        let mut refs = Refs::new();
        for item in returning.iter_mut() {
            if let SelectItem::Expr { expr, alias: _ } = item {
                self.expr(expr, &mut refs)?;
            }
        }
        let result = self.close_scope(returning).map(|_| ());
        self.scopes.pop();
        result
    }

    fn insert(&mut self, insert: &mut Insert, context: &C) -> Result<()> {
        let Insert {
            table,
            columns,
            rows,
            returning,
        } = insert;
        self.qualify(table);
        let name = table.qualified_name();
        let rules = self
            .policy
            .inserts
            .get(&table_key(table))
            .ok_or_else(|| Error::denied(format!("inserting into table {name:?} is not allowed")))?;
        if let Some(duplicate) = first_duplicate(columns) {
            return Err(Error::denied(format!("column {duplicate:?} is set more than once")));
        }
        let rule = rules
            .iter()
            .find(|rule| {
                rule.columns
                    .as_ref()
                    .is_none_or(|allowed| columns.iter().all(|c| allowed.contains(c)))
            })
            .ok_or_else(|| {
                Error::denied(format!(
                    "inserting into these columns of table {name:?} is not allowed: {}",
                    disallowed(columns, rules.iter().map(|r| r.columns.as_deref()))
                ))
            })?;

        // values cannot read the target table, but they may contain subqueries on other tables
        let mut refs = Refs::new();
        for row in rows.iter_mut() {
            self.exprs(row, &mut refs)?;
        }

        if let Some(extra) = &rule.extra {
            for (column, value) in extra(context)? {
                let column = Ident::new(column.as_str()).map_err(|e| {
                    Error::callback(format!("extra returned an invalid column {column:?}: {}", e.message()))
                })?;
                if columns.contains(&column) {
                    return Err(Error::denied(format!(
                        "column {column:?} of table {name:?} is set by the policy and cannot be set by the statement"
                    )));
                }
                columns.push(column);
                for row in rows.iter_mut() {
                    row.push(value.clone());
                }
            }
        }

        self.write_scope(table, false)?;
        self.close_write_scope(returning)
    }

    fn update(&mut self, update: &mut Update) -> Result<()> {
        let Update {
            table,
            assignments,
            selection,
            returning,
        } = update;
        self.qualify(table);
        let name = table.qualified_name();
        let rules = self
            .policy
            .updates
            .get(&table_key(table))
            .ok_or_else(|| Error::denied(format!("updating table {name:?} is not allowed")))?;
        let columns: Vec<Ident> = assignments.iter().map(|a| a.column.clone()).collect();
        if let Some(duplicate) = first_duplicate(&columns) {
            return Err(Error::denied(format!("column {duplicate:?} is set more than once")));
        }
        let fits = |allowed: &Option<Vec<Ident>>| {
            allowed
                .as_ref()
                .is_none_or(|allowed| columns.iter().all(|c| allowed.contains(c)))
        };
        if !rules.iter().any(|rule| fits(&rule.columns)) {
            return Err(Error::denied(format!(
                "updating these columns of table {name:?} is not allowed: {}",
                disallowed(&columns, rules.iter().map(|r| r.columns.as_deref()))
            )));
        }
        if selection.is_none() && !rules.iter().any(|rule| fits(&rule.columns) && rule.allow_unfiltered) {
            return Err(Error::denied(format!(
                "UPDATE of table {name:?} without a WHERE clause is not allowed"
            )));
        }

        self.write_scope(table, true)?;
        let mut refs = Refs::new();
        let result = (|| {
            for assignment in assignments.iter_mut() {
                self.expr(&mut assignment.value, &mut refs)?;
            }
            if let Some(selection) = selection {
                self.expr(selection, &mut refs)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => self.close_write_scope(returning),
            Err(e) => {
                self.scopes.pop();
                Err(e)
            }
        }
    }

    fn delete(&mut self, delete: &mut Delete) -> Result<()> {
        let Delete {
            table,
            selection,
            returning,
        } = delete;
        self.qualify(table);
        let name = table.qualified_name();
        let rule = self
            .policy
            .deletes
            .get(&table_key(table))
            .ok_or_else(|| Error::denied(format!("deleting from table {name:?} is not allowed")))?;
        if selection.is_none() && !rule.allow_unfiltered {
            return Err(Error::denied(format!(
                "DELETE from table {name:?} without a WHERE clause is not allowed"
            )));
        }
        self.write_scope(table, true)?;
        let mut refs = Refs::new();
        if let Some(selection) = selection
            && let Err(e) = self.expr(selection, &mut refs)
        {
            self.scopes.pop();
            return Err(e);
        }
        self.close_write_scope(returning)
    }
}

impl Instance<'_> {
    /// A base table every one of whose rules allows all columns.
    fn open_base_only(&self) -> bool {
        match &self.kind {
            InstanceKind::Base { rules, .. } => !rules.is_empty() && rules.iter().all(|rule| rule.columns.is_none()),
            InstanceKind::Derived { .. } => false,
        }
    }
}

fn binary_op(op: BinaryOperator) -> Op {
    match op {
        BinaryOperator::Eq => Op::Eq,
        BinaryOperator::NotEq => Op::NotEq,
        BinaryOperator::Lt => Op::Lt,
        BinaryOperator::LtEq => Op::LtEq,
        BinaryOperator::Gt => Op::Gt,
        BinaryOperator::GtEq => Op::GtEq,
        BinaryOperator::And => Op::And,
        BinaryOperator::Or => Op::Or,
        BinaryOperator::Plus => Op::Plus,
        BinaryOperator::Minus => Op::Minus,
        BinaryOperator::Multiply => Op::Multiply,
        BinaryOperator::Divide => Op::Divide,
        BinaryOperator::Modulo => Op::Modulo,
        BinaryOperator::Concat => Op::Concat,
        BinaryOperator::RegexMatch
        | BinaryOperator::RegexIMatch
        | BinaryOperator::RegexNotMatch
        | BinaryOperator::RegexNotIMatch => Op::Regex,
        BinaryOperator::JsonGet
        | BinaryOperator::JsonGetText
        | BinaryOperator::JsonPath
        | BinaryOperator::JsonPathText => Op::Json,
        BinaryOperator::Contains | BinaryOperator::ContainedBy => Op::Contains,
    }
}

fn operators_allowed(used: OpSet, allowed: OpSet, table: Option<&str>) -> Result<()> {
    let missing = used.missing_from(allowed);
    if missing.is_empty() {
        return Ok(());
    }
    let list = missing.iter().map(|op| op.as_str()).collect::<Vec<_>>().join(", ");
    Err(Error::denied(match table {
        Some(table) => format!("operator not allowed on table {table:?}: {list}"),
        None => format!("operator not allowed: {list}"),
    }))
}

/// An output position is only meaningful when p14g is not about to change the select list.
fn checked_ordinal(number: &str, columns: usize, has_wildcard: bool) -> Result<u32> {
    if has_wildcard {
        return Err(Error::denied(
            "a column position cannot be used together with * in the select list",
        ));
    }
    ordinal(number, columns)
}

/// A position in the select list, written as a number in `ORDER BY` or `GROUP BY`.
fn ordinal(number: &str, columns: usize) -> Result<u32> {
    number
        .parse::<u32>()
        .ok()
        .filter(|&n| n >= 1 && n as usize <= columns)
        .ok_or_else(|| Error::denied(format!("{number} is not a position in the select list")))
}

fn first_duplicate(columns: &[Ident]) -> Option<&Ident> {
    let mut seen = BTreeSet::new();
    columns.iter().find(|column| !seen.insert(*column))
}

/// The columns no rule allows, for an error message.
fn disallowed<'a>(columns: &[Ident], rules: impl Iterator<Item = Option<&'a [Ident]>>) -> String {
    let allowed: Vec<&[Ident]> = rules.flatten().collect();
    let bad: Vec<&str> = columns
        .iter()
        .filter(|c| !allowed.iter().any(|rule| rule.contains(c)))
        .map(Ident::as_str)
        .collect();
    if bad.is_empty() {
        // each column is allowed by some rule, just not all by the same one
        columns.iter().map(Ident::as_str).collect::<Vec<_>>().join(", ")
    } else {
        bad.join(", ")
    }
}
