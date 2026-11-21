//! Writing the IR out as SQL.
//!
//! The statement writer here is shared; a backend supplies the pieces that differ between databases
//! through [`Syntax`]. Output is fully parenthesised and every token is separated by a space, so operator
//! precedence never matters and two tokens can never run together into something else (`- -1` into a
//! comment, for example).

mod postgres;

use std::mem;

use crate::{
    ast::{
        BinaryOperator, Column, DataType, DateField, Delete, Expr, Function, FunctionArgs, Ident, Insert, IsTest, Join,
        JoinKind, LikeKind, Literal, OrderBy, Query, Select, SelectItem, SetExpr, SetOperator, Statement, Table,
        TableFactor, UnaryOperator, Update,
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

pub(crate) fn write(
    backend: Backend,
    statement: &Statement,
    literals: Literals,
    max_placeholder: u32,
) -> Result<Written> {
    match backend {
        Backend::Postgres => Writer::new(&postgres::Postgres, literals, max_placeholder).finish(statement),
    }
}

/// How a function call starts, up to but not including its arguments.
pub(crate) enum FunctionHead {
    /// Written as is, with no argument list at all.
    Bare(&'static str),
    /// Followed by `(args)`.
    Call(String),
}

/// What differs between databases.
pub(crate) trait Syntax {
    fn ident(&self, out: &mut String, ident: &Ident);
    /// Write a string literal. Only called once the value is known to have no NUL byte.
    fn string(&self, out: &mut String, value: &str);
    fn placeholder(&self, out: &mut String, number: u32);
    fn data_type(&self, out: &mut String, data_type: DataType);
    fn function_head(&self, function: &Function) -> Result<FunctionHead>;
}

struct Writer<'a, S> {
    syntax: &'a S,
    literals: Literals,
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
    fn new(syntax: &'a S, literals: Literals, max_placeholder: u32) -> Self {
        Self {
            syntax,
            literals,
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

    fn ident(&mut self, ident: &Ident) {
        self.syntax.ident(&mut self.out, ident);
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
                w.query(&cte.query)?;
                w.push(")");
                Ok(())
            })?;
            self.push(" ");
        }
        self.set_expr(body, false)?;
        self.order_by(order_by)?;
        if let Some(limit) = limit {
            self.push(" LIMIT ");
            self.expr(limit)?;
        }
        if let Some(offset) = offset {
            self.push(" OFFSET ");
            self.expr(offset)?;
        }
        Ok(())
    }

    /// `operand` is true for the two sides of a set operation, which are always parenthesised.
    fn set_expr(&mut self, body: &SetExpr, operand: bool) -> Result<()> {
        match body {
            SetExpr::Select(select) if !operand => self.select(select),
            SetExpr::Query(query) => {
                self.push("(");
                self.query(query)?;
                self.push(")");
                Ok(())
            }
            SetExpr::SetOperation { op, all, left, right } if !operand => {
                self.set_expr(left, true)?;
                self.push(match op {
                    SetOperator::Union => " UNION ",
                    SetOperator::Except => " EXCEPT ",
                    SetOperator::Intersect => " INTERSECT ",
                });
                if *all {
                    self.push("ALL ");
                }
                self.set_expr(right, true)
            }
            SetExpr::Select(_) | SetExpr::SetOperation { .. } => {
                self.push("(");
                self.set_expr(body, false)?;
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
            self.push(" FROM ");
            self.list(from, |w, table| {
                w.factor(&table.relation)?;
                table.joins.iter().try_for_each(|join| w.join(join))
            })?;
        }
        if let Some(selection) = selection {
            self.push(" WHERE ");
            self.expr(selection)?;
        }
        if !group_by.is_empty() {
            self.push(" GROUP BY ");
            self.list(group_by, Self::expr)?;
        }
        if let Some(having) = having {
            self.push(" HAVING ");
            self.expr(having)?;
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
                    w.expr(expr)?;
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
        let Table { schema, name, alias } = table;
        if let Some(schema) = schema {
            self.ident(schema);
            self.push(".");
        }
        self.ident(name);
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
                self.query(subquery)?;
                self.push(") AS ");
                self.ident(alias);
            }
        }
        Ok(())
    }

    fn join(&mut self, join: &Join) -> Result<()> {
        let Join { kind, relation, on } = join;
        self.push(match kind {
            JoinKind::Inner => " INNER JOIN ",
            JoinKind::Left => " LEFT JOIN ",
            JoinKind::Right => " RIGHT JOIN ",
            JoinKind::Full => " FULL JOIN ",
            JoinKind::Cross => " CROSS JOIN ",
        });
        self.factor(relation)?;
        match (kind, on) {
            (JoinKind::Cross, None) => Ok(()),
            (JoinKind::Cross, Some(_)) => Err(invalid("a CROSS JOIN cannot have a condition")),
            (_, Some(on)) => {
                self.push(" ON ");
                self.expr(on)
            }
            (_, None) => Err(invalid("a join needs a condition")),
        }
    }

    fn order_by(&mut self, order_by: &[OrderBy]) -> Result<()> {
        if !order_by.is_empty() {
            self.push(" ");
        }
        self.order_by_items(order_by)
    }

    fn order_by_items(&mut self, order_by: &[OrderBy]) -> Result<()> {
        if order_by.is_empty() {
            return Ok(());
        }
        self.push("ORDER BY ");
        self.list(order_by, |w, item| {
            let OrderBy {
                expr,
                descending,
                nulls_first,
            } = item;
            w.expr(expr)?;
            match descending {
                Some(true) => w.push(" DESC"),
                Some(false) => w.push(" ASC"),
                None => {}
            }
            match nulls_first {
                Some(true) => w.push(" NULLS FIRST"),
                Some(false) => w.push(" NULLS LAST"),
                None => {}
            }
            Ok(())
        })
    }

    fn returning(&mut self, returning: &[SelectItem]) -> Result<()> {
        if returning.is_empty() {
            return Ok(());
        }
        self.push(" RETURNING ");
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
        self.push("INSERT INTO ");
        self.table(table);
        self.push(" (");
        // column lists and SET targets are bare names: Postgres does not accept qualified ones there
        self.list(columns, |w, column| {
            w.ident(column);
            Ok(())
        })?;
        self.push(") VALUES ");
        self.list(rows, |w, row| {
            if row.len() != columns.len() {
                return Err(invalid("an INSERT row does not match the column list"));
            }
            w.push("(");
            w.list(row, Self::expr)?;
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
        self.push(" SET ");
        self.list(assignments, |w, assignment| {
            w.ident(&assignment.column);
            w.push(" = ");
            w.expr(&assignment.value)
        })?;
        if let Some(selection) = selection {
            self.push(" WHERE ");
            self.expr(selection)?;
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
            self.push(" WHERE ");
            self.expr(selection)?;
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
                match self.literals {
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

    /// Write `(` open … `)` around whatever `inner` writes.
    fn parens(&mut self, inner: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.push("(");
        inner(self)?;
        self.push(")");
        Ok(())
    }

    fn expr(&mut self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Column(Column { table, name }) => {
                if let Some(table) = table {
                    self.ident(table);
                    self.push(".");
                }
                self.ident(name);
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
            Expr::OutputColumn(name) => {
                self.ident(name);
                Ok(())
            }
            Expr::Ordinal(position) => {
                self.push(&position.to_string());
                Ok(())
            }
            Expr::Unary { op, expr } => self.parens(|w| {
                w.push(match op {
                    UnaryOperator::Not => "NOT ",
                    UnaryOperator::Minus => "- ",
                    UnaryOperator::Plus => "+ ",
                });
                w.expr(expr)
            }),
            Expr::Binary { left, op, right } => self.parens(|w| {
                w.expr(left)?;
                w.push(binary_operator(*op));
                w.expr(right)
            }),
            Expr::Is { expr, test, negated } => self.parens(|w| {
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
            Expr::IsDistinctFrom { left, right, negated } => self.parens(|w| {
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
                self.parens(|w| {
                    w.expr(expr)?;
                    w.push(if *negated { " NOT IN (" } else { " IN (" });
                    w.list(list, Self::expr)?;
                    w.push(")");
                    Ok(())
                })
            }
            Expr::InSubquery {
                expr,
                subquery,
                negated,
            } => self.parens(|w| {
                w.expr(expr)?;
                w.push(if *negated { " NOT IN (" } else { " IN (" });
                w.query(subquery)?;
                w.push(")");
                Ok(())
            }),
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => self.parens(|w| {
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
            } => self.parens(|w| {
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
                self.parens(|w| {
                    w.push("CASE");
                    if let Some(operand) = operand {
                        w.push(" ");
                        w.expr(operand)?;
                    }
                    for (condition, result) in branches {
                        w.push(" WHEN ");
                        w.expr(condition)?;
                        w.push(" THEN ");
                        w.expr(result)?;
                    }
                    if let Some(else_result) = else_result {
                        w.push(" ELSE ");
                        w.expr(else_result)?;
                    }
                    w.push(" END");
                    Ok(())
                })
            }
            Expr::Cast { expr, data_type } => {
                self.push("CAST(");
                self.expr(expr)?;
                self.push(" AS ");
                self.syntax.data_type(&mut self.out, *data_type);
                self.push(")");
                Ok(())
            }
            Expr::Extract { field, expr } => {
                self.push("EXTRACT(");
                self.push(date_field(*field));
                self.push(" FROM ");
                self.expr(expr)?;
                self.push(")");
                Ok(())
            }
            Expr::Function(function) => self.function(function),
            Expr::Exists { subquery, negated } => self.parens(|w| {
                w.push(if *negated { "NOT EXISTS (" } else { "EXISTS (" });
                w.query(subquery)?;
                w.push(")");
                Ok(())
            }),
            Expr::Subquery(subquery) => self.parens(|w| w.query(subquery)),
        }
    }

    fn function(&mut self, function: &Function) -> Result<()> {
        let Function {
            schema: _,
            name: _,
            args,
            distinct,
            order_by,
            filter,
            over,
        } = function;
        match self.syntax.function_head(function)? {
            FunctionHead::Bare(keyword) => {
                self.push(keyword);
                return Ok(());
            }
            FunctionHead::Call(head) => self.push(&head),
        }
        self.push("(");
        if *distinct {
            self.push("DISTINCT ");
        }
        match args {
            FunctionArgs::Niladic => return Err(invalid("this function needs an argument list")),
            FunctionArgs::Star => self.push("*"),
            FunctionArgs::List(args) => self.list(args, Self::expr)?,
        }
        self.order_by(order_by)?;
        self.push(")");
        if let Some(filter) = filter {
            self.push(" FILTER (WHERE ");
            self.expr(filter)?;
            self.push(")");
        }
        if let Some(window) = over {
            self.push(" OVER (");
            if !window.partition_by.is_empty() {
                self.push("PARTITION BY ");
                self.list(&window.partition_by, Self::expr)?;
                if !window.order_by.is_empty() {
                    self.push(" ");
                }
            }
            self.order_by_items(&window.order_by)?;
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
