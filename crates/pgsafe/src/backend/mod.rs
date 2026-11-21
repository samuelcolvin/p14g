//! Writing the IR out as SQL.
//!
//! The statement writer here is shared; a backend supplies the pieces that differ between databases
//! through [`Syntax`]. An expression that is an operand of another is always parenthesised, and every token
//! is separated by a space, so operator precedence never matters and two tokens can never run together
//! into something else (`- -1` into a comment, for example). The two exceptions are an expression with a
//! clause to itself, and chains of `AND` or of `OR`, which read the same however they are grouped.

mod keywords;
mod postgres;

use std::mem;

use crate::{
    ast::{
        BinaryOperator, Column, DataType, DateField, Delete, Expr, Function, FunctionArgs, Ident, Insert, IsTest, Join,
        JoinKind, KeyExpr, LikeKind, Literal, OrderBy, Query, Select, SelectItem, SetExpr, SetOperator, SortExpr,
        Statement, Table, TableFactor, TrimSide, UnaryOperator, Update, VariadicFunction,
    },
    error::{Error, ErrorKind, Result},
    policy::Literals,
};

/// The database the output is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Backend {
    #[default]
    Postgres,
}

pub(crate) struct Written {
    pub sql: String,
    pub params: Vec<String>,
}

/// Which identifiers are written in double quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuoteIdentifiers {
    /// Only the ones that need it: anything that is not a lower case name made of letters, digits and
    /// underscores, and every Postgres keyword.
    #[default]
    Minimal,
    /// All of them.
    Always,
}

impl QuoteIdentifiers {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "always" => Ok(Self::Always),
            _ => Err(Error::config(format!("unknown quote_identifiers {s:?}"))),
        }
    }
}

/// How the output is laid out. It is the same statement either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Layout {
    /// Each clause of the statement on its own line. Subqueries stay on one line.
    #[default]
    Multiline,
    /// Everything on one line.
    Dense,
}

impl Layout {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "multiline" => Ok(Self::Multiline),
            "dense" => Ok(Self::Dense),
            _ => Err(Error::config(format!("unknown layout {s:?}"))),
        }
    }
}

/// The choices that change how a statement is written but not what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Style {
    pub literals: Literals,
    pub quote: QuoteIdentifiers,
    pub layout: Layout,
    /// Write builtin functions with their schema.
    pub qualify_builtins: bool,
}

pub(crate) fn write(backend: Backend, statement: &Statement, style: Style, max_placeholder: u32) -> Result<Written> {
    match backend {
        Backend::Postgres => {
            let syntax = postgres::Postgres {
                quote: style.quote,
                qualify_builtins: style.qualify_builtins,
            };
            Writer::new(&syntax, style, max_placeholder).finish(statement)
        }
    }
}

/// Quote an identifier for the backend, for SQL that pgsafe writes outside of a statement.
pub(crate) fn quote_ident(backend: Backend, ident: &Ident) -> String {
    let mut out = String::new();
    match backend {
        Backend::Postgres => postgres::Postgres {
            quote: QuoteIdentifiers::Always,
            qualify_builtins: true,
        }
        .ident(&mut out, ident),
    }
    out
}

/// What differs between databases.
pub(crate) trait Syntax {
    /// Write a name that stands on its own or starts a qualified name.
    fn ident(&self, out: &mut String, ident: &Ident);
    /// Write a name that follows a `.`. Nothing is a keyword in that position, so fewer names need quoting.
    fn member(&self, out: &mut String, ident: &Ident);
    /// Write a string literal. Only called once the value is known to have no NUL byte.
    fn string(&self, out: &mut String, value: &str);
    fn placeholder(&self, out: &mut String, number: u32);
    fn data_type(&self, out: &mut String, data_type: DataType);
    /// Write the name of a function in the catalog.
    fn function_name(&self, out: &mut String, schema: Option<&Ident>, name: &Ident);
}

struct Writer<'a, S> {
    syntax: &'a S,
    style: Style,
    /// How many subqueries deep the writer is. Only the outermost statement is laid out over several lines.
    nested: usize,
    /// Finished text. A new segment starts after each parameter pgsafe adds, because their numbers are
    /// only known once the highest placeholder in the statement is.
    segments: Vec<String>,
    out: String,
    params: Vec<String>,
    max_placeholder: u32,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Unsupported, message)
}

/// An unsigned decimal number: digits, an optional fraction and an optional exponent.
fn valid_number(number: &str) -> bool {
    let (mantissa, exponent) = match number.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, Some(exponent)),
        None => (number, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    number.len() <= 400
        && digits(whole)
        && digits(fraction)
        && !(whole.is_empty() && fraction.is_empty())
        && exponent_ok
}

impl<'a, S: Syntax> Writer<'a, S> {
    fn new(syntax: &'a S, style: Style, max_placeholder: u32) -> Self {
        Self {
            syntax,
            style,
            nested: 0,
            segments: Vec::new(),
            out: String::new(),
            params: Vec::new(),
            max_placeholder,
        }
    }

    fn finish(mut self, statement: &Statement) -> Result<Written> {
        match statement {
            Statement::Query(query) => self.query(query)?,
            Statement::Insert(insert) => self.insert(insert)?,
            Statement::Update(update) => self.update(update)?,
            Statement::Delete(delete) => self.delete(delete)?,
        }
        let mut sql = String::new();
        for (index, segment) in self.segments.iter().enumerate() {
            sql.push_str(segment);
            let offset = u32::try_from(index + 1).map_err(|_| invalid("too many parameters"))?;
            let number = self
                .max_placeholder
                .checked_add(offset)
                .ok_or_else(|| invalid("too many parameters"))?;
            self.syntax.placeholder(&mut sql, number);
        }
        sql.push_str(&self.out);
        Ok(Written {
            sql,
            params: self.params,
        })
    }

    fn push(&mut self, text: &str) {
        self.out.push_str(text);
    }

    /// Start a clause: on a new line for the outermost statement in the multiline layout, else after a space.
    fn clause(&mut self, keyword: &str) {
        let multiline = self.style.layout == Layout::Multiline && self.nested == 0;
        self.push(if multiline { "\n" } else { " " });
        self.push(keyword);
    }

    /// Write a query that is inside another statement.
    fn subquery(&mut self, query: &Query) -> Result<()> {
        self.nested += 1;
        let result = self.query(query);
        self.nested -= 1;
        result
    }

    fn ident(&mut self, ident: &Ident) {
        self.syntax.ident(&mut self.out, ident);
    }

    /// Write `.name`.
    fn member(&mut self, ident: &Ident) {
        self.push(".");
        self.syntax.member(&mut self.out, ident);
    }

    /// Write `items` separated by `, `.
    fn list<T>(&mut self, items: &[T], mut write: impl FnMut(&mut Self, &T) -> Result<()>) -> Result<()> {
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            write(self, item)?;
        }
        Ok(())
    }

    fn query(&mut self, query: &Query) -> Result<()> {
        let Query {
            with,
            body,
            order_by,
            limit,
            offset,
        } = query;
        if !with.is_empty() {
            self.push("WITH ");
            self.list(with, |w, cte| {
                w.ident(&cte.name);
                w.push(" AS (");
                w.subquery(&cte.query)?;
                w.push(")");
                Ok(())
            })?;
            self.clause("");
        }
        self.set_expr(body, false)?;
        self.order_by(order_by)?;
        if let Some(limit) = limit {
            self.clause("LIMIT ");
            self.top(limit)?;
        }
        if let Some(offset) = offset {
            self.clause("OFFSET ");
            self.top(offset)?;
        }
        Ok(())
    }

    /// `operand` is true for the two sides of a set operation, which are always parenthesised.
    fn set_expr(&mut self, body: &SetExpr, operand: bool) -> Result<()> {
        match body {
            SetExpr::Select(select) if !operand => self.select(select),
            SetExpr::Query(query) => {
                self.push("(");
                self.subquery(query)?;
                self.push(")");
                Ok(())
            }
            SetExpr::SetOperation { op, all, left, right } if !operand => {
                self.set_expr(left, true)?;
                self.clause(match (op, all) {
                    (SetOperator::Union, false) => "UNION",
                    (SetOperator::Union, true) => "UNION ALL",
                    (SetOperator::Except, false) => "EXCEPT",
                    (SetOperator::Except, true) => "EXCEPT ALL",
                    (SetOperator::Intersect, false) => "INTERSECT",
                    (SetOperator::Intersect, true) => "INTERSECT ALL",
                });
                self.clause("");
                self.set_expr(right, true)
            }
            SetExpr::Select(_) | SetExpr::SetOperation { .. } => {
                self.push("(");
                self.nested += 1;
                let result = self.set_expr(body, false);
                self.nested -= 1;
                result?;
                self.push(")");
                Ok(())
            }
        }
    }

    fn select(&mut self, select: &Select) -> Result<()> {
        let Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
        } = select;
        self.push(if *distinct { "SELECT DISTINCT " } else { "SELECT " });
        self.select_items(projection)?;
        if !from.is_empty() {
            self.clause("FROM ");
            self.list(from, |w, table| {
                w.factor(&table.relation)?;
                table.joins.iter().try_for_each(|join| w.join(join))
            })?;
        }
        if let Some(selection) = selection {
            self.clause("WHERE ");
            self.top(selection)?;
        }
        if !group_by.is_empty() {
            self.clause("GROUP BY ");
            self.list(group_by, |w, key| w.key(key, "GROUP BY"))?;
        }
        if let Some(having) = having {
            self.clause("HAVING ");
            self.top(having)?;
        }
        Ok(())
    }

    fn select_items(&mut self, items: &[SelectItem]) -> Result<()> {
        if items.is_empty() {
            return Err(invalid("an empty select list cannot be written"));
        }
        self.list(items, |w, item| {
            match item {
                SelectItem::Expr { expr, alias } => {
                    w.top(expr)?;
                    if let Some(alias) = alias {
                        w.push(" AS ");
                        w.ident(alias);
                    }
                }
                SelectItem::Wildcard => w.push("*"),
                SelectItem::QualifiedWildcard(table) => {
                    w.ident(table);
                    w.push(".*");
                }
            }
            Ok(())
        })
    }

    fn table(&mut self, table: &Table) {
        let Table {
            schema,
            name,
            alias,
            only,
        } = table;
        if *only {
            self.push("ONLY ");
        }
        match schema {
            Some(schema) => {
                self.ident(schema);
                self.member(name);
            }
            None => self.ident(name),
        }
        if let Some(alias) = alias {
            self.push(" AS ");
            self.ident(alias);
        }
    }

    fn factor(&mut self, factor: &TableFactor) -> Result<()> {
        match factor {
            TableFactor::Table(table) => self.table(table),
            TableFactor::Derived { subquery, alias } => {
                self.push("(");
                self.subquery(subquery)?;
                self.push(") AS ");
                self.ident(alias);
            }
        }
        Ok(())
    }

    fn join(&mut self, join: &Join) -> Result<()> {
        let Join { kind, relation, on } = join;
        self.clause(match kind {
            JoinKind::Inner => "INNER JOIN ",
            JoinKind::Left => "LEFT JOIN ",
            JoinKind::Right => "RIGHT JOIN ",
            JoinKind::Full => "FULL JOIN ",
            JoinKind::Cross => "CROSS JOIN ",
        });
        self.factor(relation)?;
        match (kind, on) {
            (JoinKind::Cross, None) => Ok(()),
            (JoinKind::Cross, Some(_)) => Err(invalid("a CROSS JOIN cannot have a condition")),
            (_, Some(on)) => {
                self.push(" ON ");
                self.top(on)
            }
            (_, None) => Err(invalid("a join needs a condition")),
        }
    }

    /// Write a query's ` ORDER BY ...`, with the space before it.
    fn order_by(&mut self, order_by: &[OrderBy]) -> Result<()> {
        if order_by.is_empty() {
            return Ok(());
        }
        self.clause("ORDER BY ");
        self.list(order_by, |w, item| {
            let OrderBy {
                key,
                descending,
                nulls_first,
            } = item;
            w.key(key, "ORDER BY")?;
            w.direction(*descending, *nulls_first);
            Ok(())
        })
    }

    fn key(&mut self, key: &KeyExpr, clause: &str) -> Result<()> {
        match key {
            KeyExpr::Position(position) => {
                self.push(&position.to_string());
                Ok(())
            }
            KeyExpr::Output(name) => {
                self.ident(name);
                Ok(())
            }
            // Postgres would read a number here as a position and rejects any other constant
            KeyExpr::Expr(Expr::Literal(_)) => Err(invalid(format!(
                "a constant that is not a column position in {clause} is not supported"
            ))),
            KeyExpr::Expr(expr) => self.top(expr),
        }
    }

    /// Write the `ORDER BY ...` of an aggregate call or a window, with no space before it.
    fn sort_exprs(&mut self, order_by: &[SortExpr]) -> Result<()> {
        if order_by.is_empty() {
            return Ok(());
        }
        self.push("ORDER BY ");
        self.list(order_by, |w, item| {
            let SortExpr {
                expr,
                descending,
                nulls_first,
            } = item;
            w.top(expr)?;
            w.direction(*descending, *nulls_first);
            Ok(())
        })
    }

    fn direction(&mut self, descending: Option<bool>, nulls_first: Option<bool>) {
        match descending {
            Some(true) => self.push(" DESC"),
            Some(false) => self.push(" ASC"),
            None => {}
        }
        match nulls_first {
            Some(true) => self.push(" NULLS FIRST"),
            Some(false) => self.push(" NULLS LAST"),
            None => {}
        }
    }

    fn returning(&mut self, returning: &[SelectItem]) -> Result<()> {
        if returning.is_empty() {
            return Ok(());
        }
        self.clause("RETURNING ");
        self.select_items(returning)
    }

    fn insert(&mut self, insert: &Insert) -> Result<()> {
        let Insert {
            table,
            columns,
            rows,
            returning,
        } = insert;
        if columns.is_empty() || rows.is_empty() {
            return Err(invalid("an INSERT needs columns and rows"));
        }
        if table.only {
            return Err(invalid("INSERT cannot use ONLY"));
        }
        self.push("INSERT INTO ");
        self.table(table);
        self.push(" (");
        // column lists and SET targets are bare names: Postgres does not accept qualified ones there
        self.list(columns, |w, column| {
            w.ident(column);
            Ok(())
        })?;
        self.push(")");
        self.clause("VALUES ");
        self.list(rows, |w, row| {
            if row.len() != columns.len() {
                return Err(invalid("an INSERT row does not match the column list"));
            }
            w.push("(");
            w.list(row, Self::top)?;
            w.push(")");
            Ok(())
        })?;
        self.returning(returning)
    }

    fn update(&mut self, update: &Update) -> Result<()> {
        let Update {
            table,
            assignments,
            selection,
            returning,
        } = update;
        if assignments.is_empty() {
            return Err(invalid("an UPDATE needs assignments"));
        }
        self.push("UPDATE ");
        self.table(table);
        self.clause("SET ");
        self.list(assignments, |w, assignment| {
            w.ident(&assignment.column);
            w.push(" = ");
            w.top(&assignment.value)
        })?;
        if let Some(selection) = selection {
            self.clause("WHERE ");
            self.top(selection)?;
        }
        self.returning(returning)
    }

    fn delete(&mut self, delete: &Delete) -> Result<()> {
        let Delete {
            table,
            selection,
            returning,
        } = delete;
        self.push("DELETE FROM ");
        self.table(table);
        if let Some(selection) = selection {
            self.clause("WHERE ");
            self.top(selection)?;
        }
        self.returning(returning)
    }

    fn literal(&mut self, literal: &Literal) -> Result<()> {
        match literal {
            Literal::Null => self.push("NULL"),
            Literal::Boolean(true) => self.push("TRUE"),
            Literal::Boolean(false) => self.push("FALSE"),
            Literal::Number(number) => {
                if !valid_number(number) {
                    return Err(invalid(format!("{number:?} is not a number pgsafe can write")));
                }
                self.push(number);
            }
            Literal::String(value) => {
                if value.contains('\0') {
                    return Err(invalid("string literals may not contain NUL"));
                }
                match self.style.literals {
                    Literals::Inline => self.syntax.string(&mut self.out, value),
                    Literals::Params => {
                        self.params.push(value.clone());
                        let segment = mem::take(&mut self.out);
                        self.segments.push(segment);
                    }
                }
            }
        }
        Ok(())
    }

    /// Write what `inner` writes, inside `(` … `)` if `parens`.
    fn group(&mut self, parens: bool, inner: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        if parens {
            self.push("(");
        }
        inner(self)?;
        if parens {
            self.push(")");
        }
        Ok(())
    }

    /// Write an expression as an operand of something else: in parentheses unless it is a single term, so
    /// that operator precedence never decides how the output is read.
    fn expr(&mut self, expr: &Expr) -> Result<()> {
        self.write_expr(expr, true)
    }

    /// Write an expression that has a clause, a list item or a function argument to itself. Nothing is
    /// beside it to bind to, so it needs no parentheses of its own.
    fn top(&mut self, expr: &Expr) -> Result<()> {
        self.write_expr(expr, false)
    }

    /// Write an operand of `AND` or `OR`, leaving out the parentheses in two cases.
    ///
    /// A nested use of the same operator joins the chain: both are associative, so the grouping does not
    /// matter. A single comparison or test stands as it is: `a = 1 AND b IS NULL` relies on `AND` and `OR`
    /// binding more loosely than every comparison, which is the one piece of operator precedence the
    /// output depends on. The operands of the comparison itself are still parenthesised.
    fn chained(&mut self, operand: &Expr, chain: BinaryOperator) -> Result<()> {
        let bare = match operand {
            Expr::Binary { op, .. } => {
                *op == chain
                    || matches!(
                        op,
                        BinaryOperator::Eq
                            | BinaryOperator::NotEq
                            | BinaryOperator::Lt
                            | BinaryOperator::LtEq
                            | BinaryOperator::Gt
                            | BinaryOperator::GtEq
                    )
            }
            Expr::Is { .. }
            | Expr::InList { .. }
            | Expr::InSubquery { .. }
            | Expr::Like { .. }
            | Expr::Exists { negated: false, .. } => true,
            _ => false,
        };
        self.write_expr(operand, !bare)
    }

    fn write_expr(&mut self, expr: &Expr, parens: bool) -> Result<()> {
        match expr {
            Expr::Column(Column { table, name }) => {
                match table {
                    Some(table) => {
                        self.ident(table);
                        self.member(name);
                    }
                    None => self.ident(name),
                }
                Ok(())
            }
            Expr::Literal(literal) => self.literal(literal),
            Expr::Placeholder(number) => {
                if *number == 0 {
                    return Err(invalid("placeholders are numbered from 1"));
                }
                self.max_placeholder = self.max_placeholder.max(*number);
                self.syntax.placeholder(&mut self.out, *number);
                Ok(())
            }
            Expr::Unary { op, expr } => self.group(parens, |w| {
                w.push(match op {
                    UnaryOperator::Not => "NOT ",
                    UnaryOperator::Minus => "- ",
                    UnaryOperator::Plus => "+ ",
                });
                w.expr(expr)
            }),
            Expr::Binary { left, op, right } => self.group(parens, |w| {
                if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
                    w.chained(left, *op)?;
                    w.push(binary_operator(*op));
                    w.chained(right, *op)
                } else {
                    w.expr(left)?;
                    w.push(binary_operator(*op));
                    w.expr(right)
                }
            }),
            Expr::Is { expr, test, negated } => self.group(parens, |w| {
                w.expr(expr)?;
                w.push(if *negated { " IS NOT " } else { " IS " });
                w.push(match test {
                    IsTest::Null => "NULL",
                    IsTest::True => "TRUE",
                    IsTest::False => "FALSE",
                    IsTest::Unknown => "UNKNOWN",
                });
                Ok(())
            }),
            Expr::IsDistinctFrom { left, right, negated } => self.group(parens, |w| {
                w.expr(left)?;
                w.push(if *negated {
                    " IS NOT DISTINCT FROM "
                } else {
                    " IS DISTINCT FROM "
                });
                w.expr(right)
            }),
            Expr::InList { expr, list, negated } => {
                if list.is_empty() {
                    return Err(invalid("an empty IN list cannot be written"));
                }
                self.group(parens, |w| {
                    w.expr(expr)?;
                    w.push(if *negated { " NOT IN (" } else { " IN (" });
                    w.list(list, Self::top)?;
                    w.push(")");
                    Ok(())
                })
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated,
            } => self.group(parens, |w| {
                w.expr(expr)?;
                w.push(if *negated { " NOT IN (" } else { " IN (" });
                w.subquery(subquery)?;
                w.push(")");
                Ok(())
            }),
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => self.group(parens, |w| {
                w.expr(expr)?;
                w.push(if *negated { " NOT BETWEEN " } else { " BETWEEN " });
                w.expr(low)?;
                w.push(" AND ");
                w.expr(high)
            }),
            Expr::Like {
                kind,
                expr,
                pattern,
                escape,
                negated,
            } => self.group(parens, |w| {
                w.expr(expr)?;
                if *negated {
                    w.push(" NOT");
                }
                w.push(match kind {
                    LikeKind::Like => " LIKE ",
                    LikeKind::ILike => " ILIKE ",
                    LikeKind::SimilarTo => " SIMILAR TO ",
                });
                w.expr(pattern)?;
                if let Some(escape) = escape {
                    w.push(" ESCAPE ");
                    w.expr(escape)?;
                }
                Ok(())
            }),
            Expr::Case {
                operand,
                branches,
                else_result,
            } => {
                if branches.is_empty() {
                    return Err(invalid("a CASE needs at least one WHEN"));
                }
                self.group(parens, |w| {
                    w.push("CASE");
                    if let Some(operand) = operand {
                        w.push(" ");
                        w.top(operand)?;
                    }
                    for (condition, result) in branches {
                        w.push(" WHEN ");
                        w.top(condition)?;
                        w.push(" THEN ");
                        w.top(result)?;
                    }
                    if let Some(else_result) = else_result {
                        w.push(" ELSE ");
                        w.top(else_result)?;
                    }
                    w.push(" END");
                    Ok(())
                })
            }
            Expr::Cast { expr, data_type } => {
                self.push("CAST(");
                self.top(expr)?;
                self.push(" AS ");
                self.syntax.data_type(&mut self.out, *data_type);
                self.push(")");
                Ok(())
            }
            Expr::Extract { field, expr } => {
                self.push("EXTRACT(");
                self.push(date_field(*field));
                self.push(" FROM ");
                self.top(expr)?;
                self.push(")");
                Ok(())
            }
            Expr::Function(function) => self.function(function),
            Expr::Variadic { function, first, rest } => {
                self.push(match function {
                    VariadicFunction::Coalesce => "COALESCE(",
                    VariadicFunction::Greatest => "GREATEST(",
                    VariadicFunction::Least => "LEAST(",
                });
                self.top(first)?;
                for arg in rest {
                    self.push(", ");
                    self.top(arg)?;
                }
                self.push(")");
                Ok(())
            }
            Expr::NullIf { left, right } => {
                self.push("NULLIF(");
                self.top(left)?;
                self.push(", ");
                self.top(right)?;
                self.push(")");
                Ok(())
            }
            Expr::CurrentDate => {
                self.push("CURRENT_DATE");
                Ok(())
            }
            Expr::CurrentTimestamp => {
                self.push("CURRENT_TIMESTAMP");
                Ok(())
            }
            Expr::Trim { side, expr, characters } => {
                self.push(match side {
                    TrimSide::Both => "TRIM(BOTH ",
                    TrimSide::Leading => "TRIM(LEADING ",
                    TrimSide::Trailing => "TRIM(TRAILING ",
                });
                if let Some(characters) = characters {
                    self.expr(characters)?;
                    self.push(" ");
                }
                self.push("FROM ");
                self.expr(expr)?;
                self.push(")");
                Ok(())
            }
            Expr::Exists { subquery, negated } => self.group(parens, |w| {
                w.push(if *negated { "NOT EXISTS (" } else { "EXISTS (" });
                w.subquery(subquery)?;
                w.push(")");
                Ok(())
            }),
            // a subquery is always in parentheses, they are part of it
            Expr::Subquery(subquery) => self.group(true, |w| w.subquery(subquery)),
        }
    }

    fn function(&mut self, function: &Function) -> Result<()> {
        let Function {
            schema,
            name,
            args,
            filter,
            over,
        } = function;
        self.syntax.function_name(&mut self.out, schema.as_ref(), name);
        self.push("(");
        match args {
            FunctionArgs::Star => self.push("*"),
            FunctionArgs::List {
                args,
                distinct,
                order_by,
            } => {
                if *distinct {
                    self.push("DISTINCT ");
                }
                self.list(args, Self::top)?;
                if !args.is_empty() && !order_by.is_empty() {
                    self.push(" ");
                }
                self.sort_exprs(order_by)?;
            }
        }
        self.push(")");
        if let Some(filter) = filter {
            self.push(" FILTER (WHERE ");
            self.top(filter)?;
            self.push(")");
        }
        if let Some(window) = over {
            self.push(" OVER (");
            if !window.partition_by.is_empty() {
                self.push("PARTITION BY ");
                self.list(&window.partition_by, Self::top)?;
                if !window.order_by.is_empty() {
                    self.push(" ");
                }
            }
            self.sort_exprs(&window.order_by)?;
            self.push(")");
        }
        Ok(())
    }
}

fn binary_operator(op: BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Eq => " = ",
        BinaryOperator::NotEq => " <> ",
        BinaryOperator::Lt => " < ",
        BinaryOperator::LtEq => " <= ",
        BinaryOperator::Gt => " > ",
        BinaryOperator::GtEq => " >= ",
        BinaryOperator::And => " AND ",
        BinaryOperator::Or => " OR ",
        BinaryOperator::Plus => " + ",
        BinaryOperator::Minus => " - ",
        BinaryOperator::Multiply => " * ",
        BinaryOperator::Divide => " / ",
        BinaryOperator::Modulo => " % ",
        BinaryOperator::Concat => " || ",
        BinaryOperator::RegexMatch => " ~ ",
        BinaryOperator::RegexIMatch => " ~* ",
        BinaryOperator::RegexNotMatch => " !~ ",
        BinaryOperator::RegexNotIMatch => " !~* ",
        BinaryOperator::JsonGet => " -> ",
        BinaryOperator::JsonGetText => " ->> ",
        BinaryOperator::JsonPath => " #> ",
        BinaryOperator::JsonPathText => " #>> ",
        BinaryOperator::Contains => " @> ",
        BinaryOperator::ContainedBy => " <@ ",
    }
}

fn date_field(field: DateField) -> &'static str {
    match field {
        DateField::Century => "CENTURY",
        DateField::Day => "DAY",
        DateField::Decade => "DECADE",
        DateField::Dow => "DOW",
        DateField::Doy => "DOY",
        DateField::Epoch => "EPOCH",
        DateField::Hour => "HOUR",
        DateField::Isodow => "ISODOW",
        DateField::Isoyear => "ISOYEAR",
        DateField::Microseconds => "MICROSECONDS",
        DateField::Millennium => "MILLENNIUM",
        DateField::Milliseconds => "MILLISECONDS",
        DateField::Minute => "MINUTE",
        DateField::Month => "MONTH",
        DateField::Quarter => "QUARTER",
        DateField::Second => "SECOND",
        DateField::Week => "WEEK",
        DateField::Year => "YEAR",
    }
}
