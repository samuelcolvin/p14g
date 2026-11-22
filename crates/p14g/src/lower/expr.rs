use std::slice;

use sqlparser::ast as sp;

use super::{Lower, ident, location, name_location, object_name, qualified_name, reject};
use crate::{
    ast::{
        BinaryOperator, Column, DataType, DateField, Expr, Function, FunctionArgs, Ident, IsTest, LikeKind, Literal,
        MAX_PLACEHOLDER, TrimSide, UnaryOperator, VariadicFunction, Window,
    },
    error::{Error, Location, Result},
    functions,
    policy::FilterValue,
};

impl<'a> Lower<'a> {
    pub(super) fn expr(&mut self, expr: sp::Expr) -> Result<Expr> {
        self.nested(|this| {
            this.node()?;
            let at = cheap_location(&expr);
            this.expr_inner(expr).map_err(|e| e.at(at))
        })
    }

    fn boxed(&mut self, expr: sp::Expr) -> Result<Box<Expr>> {
        self.expr(expr).map(Box::new)
    }

    fn exprs(&mut self, exprs: Vec<sp::Expr>) -> Result<Vec<Expr>> {
        exprs.into_iter().map(|e| self.expr(e)).collect()
    }

    fn expr_inner(&mut self, expr: sp::Expr) -> Result<Expr> {
        match expr {
            sp::Expr::Identifier(name) => self.column(None, ident(name)?),
            sp::Expr::CompoundIdentifier(parts) => {
                let mut parts: Vec<Ident> = parts.into_iter().map(ident).collect::<Result<_>>()?;
                match (parts.pop(), parts.pop(), parts.is_empty()) {
                    (Some(name), Some(table), true) => self.column(Some(table), name),
                    _ => Err(Error::unsupported(
                        "a column reference with more than two parts (use table.column)",
                    )),
                }
            }
            sp::Expr::Nested(inner) => self.expr(*inner),
            sp::Expr::Value(value) => self.value(value),
            sp::Expr::TypedString(sp::TypedString {
                data_type,
                value,
                uses_odbc_syntax,
            }) => {
                reject(&uses_odbc_syntax, "ODBC literal syntax")?;
                Ok(Expr::Cast {
                    expr: Box::new(Expr::Literal(Literal::String(string_value(value)?))),
                    data_type: lower_data_type(data_type)?,
                })
            }
            sp::Expr::Interval(sp::Interval {
                value,
                leading_field,
                leading_precision,
                last_field,
                fractional_seconds_precision,
            }) => {
                reject(&leading_field, "an interval unit outside the string")?;
                reject(&leading_precision, "an interval precision")?;
                reject(&last_field, "an interval range")?;
                reject(&fractional_seconds_precision, "an interval precision")?;
                let sp::Expr::Value(value) = *value else {
                    return Err(Error::unsupported("an interval that is not a string literal"));
                };
                Ok(Expr::Cast {
                    expr: Box::new(Expr::Literal(Literal::String(string_value(value)?))),
                    data_type: DataType::Interval,
                })
            }
            sp::Expr::UnaryOp { op, expr } => {
                let op = match op {
                    sp::UnaryOperator::Not => UnaryOperator::Not,
                    sp::UnaryOperator::Minus => UnaryOperator::Minus,
                    sp::UnaryOperator::Plus => UnaryOperator::Plus,
                    _ => return Err(Error::unsupported("this unary operator")),
                };
                Ok(Expr::Unary {
                    op,
                    expr: self.boxed(*expr)?,
                })
            }
            sp::Expr::BinaryOp { left, op, right } => Ok(Expr::Binary {
                left: self.boxed(*left)?,
                op: binary_operator(&op)?,
                right: self.boxed(*right)?,
            }),
            sp::Expr::IsNull(e) => self.is(*e, IsTest::Null, false),
            sp::Expr::IsNotNull(e) => self.is(*e, IsTest::Null, true),
            sp::Expr::IsTrue(e) => self.is(*e, IsTest::True, false),
            sp::Expr::IsNotTrue(e) => self.is(*e, IsTest::True, true),
            sp::Expr::IsFalse(e) => self.is(*e, IsTest::False, false),
            sp::Expr::IsNotFalse(e) => self.is(*e, IsTest::False, true),
            sp::Expr::IsUnknown(e) => self.is(*e, IsTest::Unknown, false),
            sp::Expr::IsNotUnknown(e) => self.is(*e, IsTest::Unknown, true),
            sp::Expr::IsDistinctFrom(left, right) => Ok(Expr::IsDistinctFrom {
                left: self.boxed(*left)?,
                right: self.boxed(*right)?,
                negated: false,
            }),
            sp::Expr::IsNotDistinctFrom(left, right) => Ok(Expr::IsDistinctFrom {
                left: self.boxed(*left)?,
                right: self.boxed(*right)?,
                negated: true,
            }),
            sp::Expr::In {
                expr,
                target,
                negated,
                global,
            } => {
                reject(&global, "GLOBAL IN")?;
                let expr = self.boxed(*expr)?;
                match target {
                    sp::InTarget::List(list) => {
                        // `IN (:name)` with a list bound to the name is that list
                        if let [sp::Expr::Value(value)] = list.as_slice()
                            && let sp::Value::Placeholder(placeholder) = &value.value
                            && self.filter.is_some()
                            && let FilterValue::Many(values) = self.binding(placeholder)?
                        {
                            if values.is_empty() {
                                return Err(Error::callback(format!(
                                    "{placeholder} is an empty list, and IN () is not valid SQL"
                                )));
                            }
                            return Ok(Expr::InList {
                                expr,
                                list: values.clone(),
                                negated,
                            });
                        }
                        if list.len() > self.limits.max_in_list {
                            return Err(Error::limit(format!(
                                "IN list has more than {} items",
                                self.limits.max_in_list
                            )));
                        }
                        Ok(Expr::InList {
                            expr,
                            list: self.exprs(list)?,
                            negated,
                        })
                    }
                    sp::InTarget::Subquery(subquery) => {
                        self.count_subquery()?;
                        Ok(Expr::InSubquery {
                            expr,
                            subquery: Box::new(self.query(*subquery)?),
                            negated,
                        })
                    }
                    sp::InTarget::Unnest(_) | sp::InTarget::Table { .. } => {
                        Err(Error::unsupported("IN with anything but a list or a subquery"))
                    }
                }
            }
            sp::Expr::Between {
                expr,
                negated,
                low,
                high,
            } => Ok(Expr::Between {
                expr: self.boxed(*expr)?,
                low: self.boxed(*low)?,
                high: self.boxed(*high)?,
                negated,
            }),
            sp::Expr::Like {
                negated,
                any,
                expr,
                pattern,
                escape_char,
            } => {
                reject(&any, "LIKE ANY")?;
                self.like(LikeKind::Like, *expr, *pattern, escape_char, negated)
            }
            sp::Expr::ILike {
                negated,
                any,
                expr,
                pattern,
                escape_char,
            } => {
                reject(&any, "ILIKE ANY")?;
                self.like(LikeKind::ILike, *expr, *pattern, escape_char, negated)
            }
            sp::Expr::SimilarTo {
                negated,
                expr,
                pattern,
                escape_char,
            } => self.like(LikeKind::SimilarTo, *expr, *pattern, escape_char, negated),
            sp::Expr::Case {
                case_token: _,
                end_token: _,
                operand,
                conditions,
                else_result,
            } => Ok(Expr::Case {
                operand: operand.map(|e| self.boxed(*e)).transpose()?,
                branches: conditions
                    .into_iter()
                    .map(|sp::CaseWhen { condition, result }| Ok((self.expr(condition)?, self.expr(result)?)))
                    .collect::<Result<_>>()?,
                else_result: else_result.map(|e| self.boxed(*e)).transpose()?,
            }),
            sp::Expr::Cast {
                kind,
                expr,
                data_type,
                format,
            } => {
                if !matches!(kind, sp::CastKind::Cast | sp::CastKind::DoubleColon) {
                    return Err(Error::unsupported("TRY_CAST / SAFE_CAST"));
                }
                reject(&format, "CAST ... FORMAT")?;
                Ok(Expr::Cast {
                    expr: self.boxed(*expr)?,
                    data_type: lower_data_type(data_type)?,
                })
            }
            sp::Expr::Extract { field, syntax: _, expr } => Ok(Expr::Extract {
                field: date_field(&field)?,
                expr: self.boxed(*expr)?,
            }),
            sp::Expr::Ceil { expr, field } => self.ceil_floor("ceil", *expr, &field),
            sp::Expr::Floor { expr, field } => self.ceil_floor("floor", *expr, &field),
            sp::Expr::Position { expr, r#in } => {
                // `position(a IN b)` is grammar for `pg_catalog.position(b, a)`
                let args = vec![self.expr(*r#in)?, self.expr(*expr)?];
                builtin("position", args)
            }
            sp::Expr::Substring {
                expr,
                substring_from,
                substring_for,
                special: _,
                shorthand: _,
            } => {
                let mut args = vec![self.expr(*expr)?];
                match (substring_from, substring_for) {
                    (Some(from), Some(count)) => {
                        args.push(self.expr(*from)?);
                        args.push(self.expr(*count)?);
                    }
                    (Some(from), None) => args.push(self.expr(*from)?),
                    // `substring(x FOR n)` starts at 1
                    (None, Some(count)) => {
                        args.push(Expr::Literal(Literal::Number("1".to_owned())));
                        args.push(self.expr(*count)?);
                    }
                    (None, None) => return Err(Error::unsupported("SUBSTRING without FROM or FOR")),
                }
                builtin("substring", args)
            }
            sp::Expr::Trim {
                trim_where,
                trim_what,
                expr,
                trim_characters,
            } => {
                let side = match trim_where {
                    None | Some(sp::TrimWhereField::Both) => TrimSide::Both,
                    Some(sp::TrimWhereField::Leading) => TrimSide::Leading,
                    Some(sp::TrimWhereField::Trailing) => TrimSide::Trailing,
                };
                let characters = match (trim_what, trim_characters) {
                    (None, None) => None,
                    (Some(what), None) => Some(self.boxed(*what)?),
                    (None, Some(mut characters)) if characters.len() == 1 => {
                        Some(Box::new(self.expr(characters.remove(0))?))
                    }
                    _ => return Err(Error::unsupported("TRIM with more than one set of characters")),
                };
                Ok(Expr::Trim {
                    side,
                    expr: self.boxed(*expr)?,
                    characters,
                })
            }
            sp::Expr::Function(function) => self.function(function),
            sp::Expr::Exists { subquery, negated } => {
                self.count_subquery()?;
                Ok(Expr::Exists {
                    subquery: Box::new(self.query(*subquery)?),
                    negated,
                })
            }
            sp::Expr::Subquery(subquery) => {
                self.count_subquery()?;
                Ok(Expr::Subquery(Box::new(self.query(*subquery)?)))
            }
            sp::Expr::Wildcard(_) | sp::Expr::QualifiedWildcard(..) => {
                Err(Error::unsupported("* outside a select list"))
            }
            sp::Expr::Tuple(_) => Err(Error::unsupported("a row constructor")),
            sp::Expr::Array(_) => Err(Error::unsupported("an array constructor")),
            sp::Expr::Collate { .. } => Err(Error::unsupported("COLLATE")),
            sp::Expr::AtTimeZone { .. } => Err(Error::unsupported("AT TIME ZONE")),
            sp::Expr::AnyOp { .. } | sp::Expr::AllOp { .. } => Err(Error::unsupported("ANY / ALL")),
            _ => Err(Error::unsupported("this expression")),
        }
    }

    fn is(&mut self, expr: sp::Expr, test: IsTest, negated: bool) -> Result<Expr> {
        Ok(Expr::Is {
            expr: self.boxed(expr)?,
            test,
            negated,
        })
    }

    fn like(
        &mut self,
        kind: LikeKind,
        expr: sp::Expr,
        pattern: sp::Expr,
        escape: Option<Box<sp::Expr>>,
        negated: bool,
    ) -> Result<Expr> {
        Ok(Expr::Like {
            kind,
            expr: self.boxed(expr)?,
            pattern: self.boxed(pattern)?,
            escape: escape.map(|e| self.boxed(*e)).transpose()?,
            negated,
        })
    }

    fn ceil_floor(&mut self, name: &str, expr: sp::Expr, field: &sp::CeilFloorKind) -> Result<Expr> {
        if !matches!(field, sp::CeilFloorKind::DateTimeField(sp::DateTimeField::NoDateTime)) {
            return Err(Error::unsupported(format!("{name} with a field or scale")));
        }
        let args = vec![self.expr(expr)?];
        builtin(name, args)
    }

    fn value(&mut self, value: sp::ValueWithSpan) -> Result<Expr> {
        match value.value {
            sp::Value::Number(number, long) => {
                reject(&long, "a number with an L suffix")?;
                Ok(Expr::Literal(Literal::Number(number)))
            }
            sp::Value::Boolean(b) => Ok(Expr::Literal(Literal::Boolean(b))),
            sp::Value::Null => Ok(Expr::Literal(Literal::Null)),
            sp::Value::Placeholder(placeholder) if self.filter.is_some() => match self.binding(&placeholder)? {
                FilterValue::One(value) => Ok(value.clone()),
                FilterValue::Many(_) => Err(Error::callback(format!(
                    "{placeholder} is a list, which can only be used as IN ({placeholder})"
                ))),
            },
            sp::Value::Placeholder(placeholder) => {
                let number = placeholder
                    .strip_prefix('$')
                    .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|digits| digits.parse::<u32>().ok())
                    .filter(|&n| (1..=MAX_PLACEHOLDER).contains(&n))
                    .ok_or_else(|| Error::unsupported(format!("the placeholder {placeholder:?} (use $1, $2, ...)")))?;
                self.max_placeholder = self.max_placeholder.max(number);
                Ok(Expr::Placeholder(number))
            }
            other => Ok(Expr::Literal(Literal::String(string_value(sp::ValueWithSpan {
                value: other,
                span: value.span,
            })?))),
        }
    }

    /// A column reference. In a filter every column belongs to the rule's table, so it is qualified with the
    /// name that table goes by in the statement, and recorded.
    fn column(&mut self, table: Option<Ident>, name: Ident) -> Result<Expr> {
        let Some(filter) = &mut self.filter else {
            return Ok(Expr::Column(Column { table, name }));
        };
        if let Some(named) = &table
            && named != filter.table
            && named != filter.qualifier
        {
            return Err(Error::callback(format!("{named}.{name} is a column of another table")));
        }
        filter.columns.insert(name.clone());
        Ok(Expr::Column(Column {
            table: Some(filter.qualifier.clone()),
            name,
        }))
    }

    /// The value bound to a `:name` placeholder of a filter.
    fn binding(&self, placeholder: &str) -> Result<&'a FilterValue> {
        let name = placeholder
            .strip_prefix(':')
            .filter(|name| {
                let mut bytes = name.bytes();
                bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                    && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .ok_or_else(|| {
                Error::callback(format!(
                    "the placeholder {placeholder:?} is not supported in a filter (use :name)"
                ))
            })?;
        let value = self
            .filter
            .as_ref()
            .map_or(&[][..], |filter| filter.bindings)
            .iter()
            .find(|(bound, _)| bound == name)
            .map(|(_, value)| value)
            .ok_or_else(|| Error::callback(format!("the filter uses :{name} but no value was given for it")))?;
        let values = match value {
            FilterValue::One(value) => slice::from_ref(value),
            FilterValue::Many(values) => values.as_slice(),
        };
        if values.iter().all(is_value) {
            Ok(value)
        } else {
            Err(Error::callback(format!(
                "the value for :{name} must be a literal, a negative number or a cast from a string"
            )))
        }
    }

    fn function(&mut self, function: sp::Function) -> Result<Expr> {
        let sp::Function {
            name,
            uses_odbc_syntax,
            parameters,
            args,
            within_group,
            filter,
            null_treatment,
            over,
        } = function;
        reject(&uses_odbc_syntax, "ODBC function syntax")?;
        if !matches!(parameters, sp::FunctionArguments::None) {
            return Err(Error::unsupported("function parameters"));
        }
        reject(&within_group, "WITHIN GROUP")?;
        reject(&null_treatment, "IGNORE / RESPECT NULLS")?;
        let (schema, name) = qualified_name(name, "a function name")?;
        // `pg_catalog.lower` and `lower` are the same builtin: keep one spelling so both are written alike
        let schema = schema.filter(|schema| !(schema.as_str() == "pg_catalog" && functions::is_default(name.as_str())));

        // `None` when the call was written with no parentheses at all
        let args = match args {
            sp::FunctionArguments::None => None,
            sp::FunctionArguments::Subquery(_) => return Err(Error::unsupported("a subquery as function arguments")),
            sp::FunctionArguments::List(list) => Some(self.function_args(list)?),
        };
        let filter = filter.map(|e| self.boxed(*e)).transpose()?;
        let over = match over {
            None => None,
            Some(sp::WindowType::NamedWindow(_)) => return Err(Error::unsupported("a named window")),
            Some(sp::WindowType::WindowSpec(sp::WindowSpec {
                window_name,
                partition_by,
                order_by,
                window_frame,
            })) => {
                reject(&window_name, "a named window")?;
                reject(&window_frame, "a window frame")?;
                Some(Window {
                    partition_by: self.exprs(partition_by)?,
                    order_by: self.sort_exprs(order_by)?,
                })
            }
        };

        // Some names are grammar in Postgres rather than functions in the catalog. They become their own
        // expressions, and the grammar gives them no DISTINCT, ORDER BY, FILTER or OVER.
        if schema.is_none()
            && let Some(keyword) = Keyword::from_name(name.as_str())
        {
            let plain_args = match (args, &filter, &over) {
                (None, None, None) => None,
                (
                    Some(FunctionArgs::List {
                        args,
                        distinct: false,
                        order_by,
                    }),
                    None,
                    None,
                ) if order_by.is_empty() => Some(args),
                _ => {
                    return Err(Error::unsupported(format!(
                        "{name} with *, DISTINCT, ORDER BY, FILTER or OVER"
                    )));
                }
            };
            return keyword.expr(plain_args);
        }

        let Some(args) = args else {
            return Err(Error::unsupported(format!("the function {name} without parentheses")));
        };
        Ok(Expr::Function(Function {
            schema,
            name,
            args,
            filter,
            over,
        }))
    }

    fn function_args(&mut self, list: sp::FunctionArgumentList) -> Result<FunctionArgs> {
        let sp::FunctionArgumentList {
            duplicate_treatment,
            args,
            clauses,
        } = list;
        let distinct = matches!(duplicate_treatment, Some(sp::DuplicateTreatment::Distinct));
        let mut order_by = Vec::new();
        for clause in clauses {
            match clause {
                sp::FunctionArgumentClause::OrderBy(exprs) => order_by = self.sort_exprs(exprs)?,
                _ => return Err(Error::unsupported("this clause in function arguments")),
            }
        }
        let mut list = Vec::with_capacity(args.len());
        let mut star = false;
        for arg in args {
            match arg {
                sp::FunctionArg::Unnamed(sp::FunctionArgExpr::Expr(expr)) => list.push(self.expr(expr)?),
                sp::FunctionArg::Unnamed(sp::FunctionArgExpr::Wildcard) => star = true,
                sp::FunctionArg::Unnamed(_) => return Err(Error::unsupported("a qualified * as an argument")),
                sp::FunctionArg::Named { .. } | sp::FunctionArg::ExprNamed { .. } => {
                    return Err(Error::unsupported("named function arguments"));
                }
            }
        }
        match (star, list.is_empty()) {
            (false, _) => Ok(FunctionArgs::List {
                args: list,
                distinct,
                order_by,
            }),
            // `f(*)` is its own grammar rule in Postgres, which takes neither DISTINCT nor ORDER BY
            (true, true) if !distinct && order_by.is_empty() => Ok(FunctionArgs::Star),
            (true, true) => Err(Error::unsupported("DISTINCT or ORDER BY with * as the argument")),
            (true, false) => Err(Error::unsupported("* mixed with other arguments")),
        }
    }
}

/// The names that are grammar in Postgres, each with a fixed shape.
#[derive(Clone, Copy)]
enum Keyword {
    Variadic(VariadicFunction),
    NullIf,
    CurrentDate,
    CurrentTimestamp,
}

impl Keyword {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "coalesce" => Some(Self::Variadic(VariadicFunction::Coalesce)),
            "greatest" => Some(Self::Variadic(VariadicFunction::Greatest)),
            "least" => Some(Self::Variadic(VariadicFunction::Least)),
            "nullif" => Some(Self::NullIf),
            "current_date" => Some(Self::CurrentDate),
            "current_timestamp" => Some(Self::CurrentTimestamp),
            _ => None,
        }
    }

    /// Build the expression. `args` is `None` when the name was written with no parentheses.
    fn expr(self, args: Option<Vec<Expr>>) -> Result<Expr> {
        match (self, args) {
            (Self::CurrentDate, None) => Ok(Expr::CurrentDate),
            (Self::CurrentTimestamp, None) => Ok(Expr::CurrentTimestamp),
            (Self::CurrentDate | Self::CurrentTimestamp, Some(_)) => {
                Err(Error::unsupported("CURRENT_DATE or CURRENT_TIMESTAMP with parentheses"))
            }
            (Self::Variadic(function), Some(args)) => {
                let mut args = args.into_iter();
                let Some(first) = args.next() else {
                    return Err(Error::unsupported(format!("{} with no arguments", function.name())));
                };
                Ok(Expr::Variadic {
                    function,
                    first: Box::new(first),
                    rest: args.collect(),
                })
            }
            (Self::NullIf, Some(args)) => match <[Expr; 2]>::try_from(args) {
                Ok([left, right]) => Ok(Expr::NullIf {
                    left: Box::new(left),
                    right: Box::new(right),
                }),
                Err(args) => Err(Error::unsupported(format!("nullif with {} arguments", args.len()))),
            },
            (Self::Variadic(_) | Self::NullIf, None) => Err(Error::unsupported("this function without parentheses")),
        }
    }
}

/// Where an expression starts, when that can be read off without walking the expression.
///
/// `Spanned::span` is recursive, and expressions can be far too deep for that (see `STACK_PER_TOKEN`), so
/// this only looks at names and literals, directly or one operand down.
fn cheap_location(expr: &sp::Expr) -> Option<Location> {
    fn leaf(expr: &sp::Expr) -> Option<Location> {
        match expr {
            sp::Expr::Identifier(name) => location(name.span),
            sp::Expr::CompoundIdentifier(parts) => parts.first().and_then(|name| location(name.span)),
            sp::Expr::Value(value) => location(value.span),
            sp::Expr::TypedString(typed) => location(typed.value.span),
            sp::Expr::Function(function) => name_location(&function.name),
            _ => None,
        }
    }
    leaf(expr).or_else(|| match expr {
        sp::Expr::BinaryOp { left: inner, .. }
        | sp::Expr::UnaryOp { expr: inner, .. }
        | sp::Expr::Cast { expr: inner, .. }
        | sp::Expr::Nested(inner)
        | sp::Expr::Collate { expr: inner, .. }
        | sp::Expr::AnyOp { left: inner, .. }
        | sp::Expr::AllOp { left: inner, .. }
        | sp::Expr::AtTimeZone { timestamp: inner, .. } => leaf(inner),
        _ => None,
    })
}

/// A call to a builtin that the parser represents as dedicated syntax.
fn builtin(name: &str, args: Vec<Expr>) -> Result<Expr> {
    Ok(Expr::Function(Function::call(Ident::new(name)?, args)))
}

/// The value of a string literal, for the forms whose value sqlparser decodes the way Postgres does.
fn string_value(value: sp::ValueWithSpan) -> Result<String> {
    match value.value {
        sp::Value::SingleQuotedString(s) | sp::Value::EscapedStringLiteral(s) => Ok(s),
        sp::Value::DollarQuotedString(sp::DollarQuotedString { value, tag: _ }) => Ok(value),
        _ => Err(Error::unsupported("this kind of literal").at(location(value.span))),
    }
}

fn binary_operator(op: &sp::BinaryOperator) -> Result<BinaryOperator> {
    Ok(match op {
        sp::BinaryOperator::Eq => BinaryOperator::Eq,
        sp::BinaryOperator::NotEq => BinaryOperator::NotEq,
        sp::BinaryOperator::Lt => BinaryOperator::Lt,
        sp::BinaryOperator::LtEq => BinaryOperator::LtEq,
        sp::BinaryOperator::Gt => BinaryOperator::Gt,
        sp::BinaryOperator::GtEq => BinaryOperator::GtEq,
        sp::BinaryOperator::And => BinaryOperator::And,
        sp::BinaryOperator::Or => BinaryOperator::Or,
        sp::BinaryOperator::Plus => BinaryOperator::Plus,
        sp::BinaryOperator::Minus => BinaryOperator::Minus,
        sp::BinaryOperator::Multiply => BinaryOperator::Multiply,
        sp::BinaryOperator::Divide => BinaryOperator::Divide,
        sp::BinaryOperator::Modulo => BinaryOperator::Modulo,
        sp::BinaryOperator::StringConcat => BinaryOperator::Concat,
        sp::BinaryOperator::PGRegexMatch => BinaryOperator::RegexMatch,
        sp::BinaryOperator::PGRegexIMatch => BinaryOperator::RegexIMatch,
        sp::BinaryOperator::PGRegexNotMatch => BinaryOperator::RegexNotMatch,
        sp::BinaryOperator::PGRegexNotIMatch => BinaryOperator::RegexNotIMatch,
        sp::BinaryOperator::Arrow => BinaryOperator::JsonGet,
        sp::BinaryOperator::LongArrow => BinaryOperator::JsonGetText,
        sp::BinaryOperator::HashArrow => BinaryOperator::JsonPath,
        sp::BinaryOperator::HashLongArrow => BinaryOperator::JsonPathText,
        sp::BinaryOperator::AtArrow => BinaryOperator::Contains,
        sp::BinaryOperator::ArrowAt => BinaryOperator::ContainedBy,
        _ => return Err(Error::unsupported("this operator")),
    })
}

fn date_field(field: &sp::DateTimeField) -> Result<DateField> {
    Ok(match field {
        sp::DateTimeField::Century => DateField::Century,
        sp::DateTimeField::Day | sp::DateTimeField::Days => DateField::Day,
        sp::DateTimeField::Decade => DateField::Decade,
        sp::DateTimeField::Dow => DateField::Dow,
        sp::DateTimeField::Doy => DateField::Doy,
        sp::DateTimeField::Epoch => DateField::Epoch,
        sp::DateTimeField::Hour | sp::DateTimeField::Hours => DateField::Hour,
        sp::DateTimeField::Isodow => DateField::Isodow,
        sp::DateTimeField::Isoyear => DateField::Isoyear,
        sp::DateTimeField::Microsecond | sp::DateTimeField::Microseconds => DateField::Microseconds,
        sp::DateTimeField::Millenium | sp::DateTimeField::Millennium => DateField::Millennium,
        sp::DateTimeField::Millisecond | sp::DateTimeField::Milliseconds => DateField::Milliseconds,
        sp::DateTimeField::Minute | sp::DateTimeField::Minutes => DateField::Minute,
        sp::DateTimeField::Month | sp::DateTimeField::Months => DateField::Month,
        sp::DateTimeField::Quarter => DateField::Quarter,
        sp::DateTimeField::Second | sp::DateTimeField::Seconds => DateField::Second,
        sp::DateTimeField::Week(None) | sp::DateTimeField::Weeks => DateField::Week,
        sp::DateTimeField::Year | sp::DateTimeField::Years => DateField::Year,
        _ => return Err(Error::unsupported("this EXTRACT field")),
    })
}

fn narrow<T: TryFrom<u64>>(value: u64, what: &str) -> Result<T> {
    T::try_from(value).map_err(|_| Error::unsupported(format!("a {what} of {value}")))
}

/// A type modifier, which Postgres reads as an int4: a larger one is a syntax error in `varchar(n)` and out of range
/// in `numeric(p)`. It came from a u64, so it is not negative.
fn modifier(value: u64, what: &str) -> Result<u32> {
    narrow::<i32>(value, what).map(i32::unsigned_abs)
}

fn lower_data_type(data_type: sp::DataType) -> Result<DataType> {
    let no_width = |width: Option<u64>, data_type: DataType| match width {
        None => Ok(data_type),
        Some(_) => Err(Error::unsupported("a display width on an integer type")),
    };
    match data_type {
        sp::DataType::SmallInt(w) | sp::DataType::Int2(w) => no_width(w, DataType::SmallInt),
        sp::DataType::Int(w) | sp::DataType::Integer(w) | sp::DataType::Int4(w) => no_width(w, DataType::Integer),
        sp::DataType::BigInt(w) | sp::DataType::Int8(w) => no_width(w, DataType::BigInt),
        sp::DataType::Numeric(info) | sp::DataType::Decimal(info) | sp::DataType::Dec(info) => {
            Ok(DataType::Numeric(match info {
                sp::ExactNumberInfo::None => None,
                sp::ExactNumberInfo::Precision(p) => Some((modifier(p, "precision")?, None)),
                sp::ExactNumberInfo::PrecisionAndScale(p, s) => Some((
                    modifier(p, "precision")?,
                    Some(i32::try_from(s).map_err(|_| Error::unsupported(format!("a scale of {s}")))?),
                )),
            }))
        }
        sp::DataType::Real | sp::DataType::Float4 => Ok(DataType::Real),
        sp::DataType::DoublePrecision | sp::DataType::Float8 => Ok(DataType::DoublePrecision),
        sp::DataType::Float(sp::ExactNumberInfo::None) => Ok(DataType::DoublePrecision),
        sp::DataType::Text => Ok(DataType::Text),
        sp::DataType::Varchar(length) | sp::DataType::CharacterVarying(length) | sp::DataType::CharVarying(length) => {
            Ok(DataType::Varchar(match length {
                None => None,
                Some(sp::CharacterLength::IntegerLength { length, unit: None }) => Some(modifier(length, "length")?),
                Some(_) => return Err(Error::unsupported("this varchar length")),
            }))
        }
        sp::DataType::Bool | sp::DataType::Boolean => Ok(DataType::Boolean),
        sp::DataType::Date => Ok(DataType::Date),
        sp::DataType::Time(None, sp::TimezoneInfo::None | sp::TimezoneInfo::WithoutTimeZone) => Ok(DataType::Time),
        sp::DataType::Timestamp(None, sp::TimezoneInfo::None | sp::TimezoneInfo::WithoutTimeZone) => {
            Ok(DataType::Timestamp)
        }
        sp::DataType::Timestamp(None, sp::TimezoneInfo::WithTimeZone | sp::TimezoneInfo::Tz) => {
            Ok(DataType::TimestampTz)
        }
        sp::DataType::Interval {
            fields: None,
            precision: None,
        } => Ok(DataType::Interval),
        sp::DataType::Uuid => Ok(DataType::Uuid),
        sp::DataType::JSON => Ok(DataType::Json),
        sp::DataType::JSONB => Ok(DataType::Jsonb),
        sp::DataType::Bytea => Ok(DataType::Bytea),
        // the parser does not know every Postgres spelling, so a few arrive as custom type names
        sp::DataType::Custom(name, modifiers) if modifiers.is_empty() => {
            let name = object_name(name, "a type name", 1)?.remove(0);
            match name.as_str() {
                "timestamptz" => Ok(DataType::TimestampTz),
                "float4" => Ok(DataType::Real),
                "float8" => Ok(DataType::DoublePrecision),
                "int2" => Ok(DataType::SmallInt),
                "int4" => Ok(DataType::Integer),
                "int8" => Ok(DataType::BigInt),
                other => Err(Error::unsupported(format!("the type {other}"))),
            }
        }
        _ => Err(Error::unsupported("this type")),
    }
}

/// Whether a value bound to a filter's placeholder is a value: one of the shapes `Expr`'s `From` impls build.
///
/// It goes into the statement as it is. A column in it would be neither qualified with the filter's table nor
/// recorded among the columns the filter reads, which an `UPDATE` must not set, and a `$n` would not be counted
/// when p14g numbers the parameters it adds.
fn is_value(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(_) => true,
        Expr::Unary {
            op: UnaryOperator::Minus,
            expr,
        } => matches!(**expr, Expr::Literal(Literal::Number(_))),
        Expr::Cast { expr, data_type: _ } => matches!(**expr, Expr::Literal(Literal::String(_))),
        _ => false,
    }
}
