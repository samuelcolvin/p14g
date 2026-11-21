//! The pgsafe intermediate representation.
//!
//! This is the only thing the SQL writer ever sees. It is deliberately small and closed: SQL that has no
//! representation here cannot be emitted, so new syntax is rejected until it is added on purpose. No node
//! carries raw SQL text.

use std::fmt;

use crate::error::{Error, ErrorKind, Result};

/// Postgres truncates identifiers longer than this (`NAMEDATALEN - 1`), which would let two names that
/// are distinct to pgsafe collide in the database.
pub const MAX_IDENT_BYTES: usize = 63;

/// A validated identifier: not empty, no NUL byte, at most [`MAX_IDENT_BYTES`] bytes.
///
/// Holds the name exactly as Postgres will see it; it is always written double-quoted.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ident(String);

impl Ident {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            Err(Error::new(ErrorKind::Unsupported, "empty identifiers are not allowed"))
        } else if value.contains('\0') {
            Err(Error::new(ErrorKind::Unsupported, "identifiers may not contain NUL"))
        } else if value.len() > MAX_IDENT_BYTES {
            Err(Error::new(
                ErrorKind::Unsupported,
                format!("identifier {value:?} is longer than {MAX_IDENT_BYTES} bytes"),
            ))
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Statement {
    Query(Query),
    Insert(Insert),
    Update(Update),
    Delete(Delete),
}

/// The kind of a statement, used to restrict what a single `rewrite` call may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementKind {
    Select,
    Insert,
    Update,
    Delete,
}

impl StatementKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "select" => Ok(Self::Select),
            "insert" => Ok(Self::Insert),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            _ => Err(Error::config(format!("unknown statement kind {s:?}"))),
        }
    }
}

impl Statement {
    #[must_use]
    pub fn kind(&self) -> StatementKind {
        match self {
            Self::Query(_) => StatementKind::Select,
            Self::Insert(_) => StatementKind::Insert,
            Self::Update(_) => StatementKind::Update,
            Self::Delete(_) => StatementKind::Delete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Query {
    pub with: Vec<Cte>,
    pub body: SetExpr,
    pub order_by: Vec<OrderBy>,
    pub limit: Option<Expr>,
    pub offset: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cte {
    pub name: Ident,
    pub query: Query,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetExpr {
    Select(Box<Select>),
    /// A parenthesised query used as an operand of a set operation.
    Query(Box<Query>),
    SetOperation {
        op: SetOperator,
        all: bool,
        left: Box<Self>,
        right: Box<Self>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetOperator {
    Union,
    Except,
    Intersect,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Select {
    pub distinct: bool,
    pub projection: Vec<SelectItem>,
    pub from: Vec<TableWithJoins>,
    pub selection: Option<Expr>,
    pub group_by: Vec<KeyExpr>,
    pub having: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelectItem {
    Expr {
        expr: Expr,
        alias: Option<Ident>,
    },
    /// `*`
    Wildcard,
    /// `alias.*`
    QualifiedWildcard(Ident),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableWithJoins {
    pub relation: TableFactor,
    pub joins: Vec<Join>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TableFactor {
    Table(Table),
    Derived { subquery: Box<Query>, alias: Ident },
}

/// A reference to a table or view, as it appears in `FROM` or as the target of a write.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Table {
    pub schema: Option<Ident>,
    pub name: Ident,
    pub alias: Option<Ident>,
    /// Written `ONLY name`: rows of inheritance children and partitions are left out.
    pub only: bool,
}

impl Table {
    /// The name columns of this table are qualified with: the alias if there is one, else the table name.
    #[must_use]
    pub fn reference_name(&self) -> &Ident {
        self.alias.as_ref().unwrap_or(&self.name)
    }

    /// `schema.name` or just `name`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        match &self.schema {
            Some(schema) => format!("{schema}.{}", self.name),
            None => self.name.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Join {
    pub kind: JoinKind,
    pub relation: TableFactor,
    /// `None` only for [`JoinKind::Cross`].
    pub on: Option<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
}

/// An item of a query's `ORDER BY`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderBy {
    pub key: KeyExpr,
    /// `Some(true)` for `DESC`, `Some(false)` for `ASC`, `None` when not given.
    pub descending: Option<bool>,
    pub nulls_first: Option<bool>,
}

/// What a query's `ORDER BY` or `GROUP BY` item refers to.
///
/// In these two clauses Postgres reads a bare integer as a position in the select list and a bare name as
/// an output column, neither of which is an expression anywhere else. A bare constant of any other kind
/// is a syntax error there, so [`KeyExpr::Expr`] holding a literal cannot be written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyExpr {
    /// A position in the select list, counted from 1.
    Position(u32),
    /// An output column, by the name it has in the select list.
    Output(Ident),
    Expr(Expr),
}

/// An item of the `ORDER BY` inside an aggregate call or a window, where it is always an expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SortExpr {
    pub expr: Expr,
    /// `Some(true)` for `DESC`, `Some(false)` for `ASC`, `None` when not given.
    pub descending: Option<bool>,
    pub nulls_first: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Expr {
    Column(Column),
    Literal(Literal),
    /// `$n` from the input.
    Placeholder(u32),
    Unary {
        op: UnaryOperator,
        expr: Box<Self>,
    },
    Binary {
        left: Box<Self>,
        op: BinaryOperator,
        right: Box<Self>,
    },
    Is {
        expr: Box<Self>,
        test: IsTest,
        negated: bool,
    },
    IsDistinctFrom {
        left: Box<Self>,
        right: Box<Self>,
        negated: bool,
    },
    InList {
        expr: Box<Self>,
        list: Vec<Self>,
        negated: bool,
    },
    InSubquery {
        expr: Box<Self>,
        subquery: Box<Query>,
        negated: bool,
    },
    Between {
        expr: Box<Self>,
        low: Box<Self>,
        high: Box<Self>,
        negated: bool,
    },
    Like {
        kind: LikeKind,
        expr: Box<Self>,
        pattern: Box<Self>,
        escape: Option<Box<Self>>,
        negated: bool,
    },
    Case {
        operand: Option<Box<Self>>,
        branches: Vec<(Self, Self)>,
        else_result: Option<Box<Self>>,
    },
    Cast {
        expr: Box<Self>,
        data_type: DataType,
    },
    Extract {
        field: DateField,
        expr: Box<Self>,
    },
    Function(Function),
    /// `COALESCE`, `GREATEST` or `LEAST`. These are grammar in Postgres, not functions in `pg_catalog`, and
    /// take one argument or more.
    Variadic {
        function: VariadicFunction,
        first: Box<Self>,
        rest: Vec<Self>,
    },
    /// `NULLIF(left, right)`
    NullIf {
        left: Box<Self>,
        right: Box<Self>,
    },
    /// `CURRENT_DATE`
    CurrentDate,
    /// `CURRENT_TIMESTAMP`
    CurrentTimestamp,
    /// `TRIM([BOTH | LEADING | TRAILING] [characters] FROM expr)`
    Trim {
        side: TrimSide,
        expr: Box<Self>,
        characters: Option<Box<Self>>,
    },
    Exists {
        subquery: Box<Query>,
        negated: bool,
    },
    Subquery(Box<Query>),
}

/// A column reference. After checking, `table` is always set to the alias of the table it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Column {
    pub table: Option<Ident>,
    pub name: Ident,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Literal {
    Null,
    Boolean(bool),
    /// An unsigned decimal number, kept as text so no precision is lost. Validated when written.
    Number(String),
    String(String),
}

impl From<bool> for Literal {
    fn from(v: bool) -> Self {
        Self::Boolean(v)
    }
}

impl From<&str> for Literal {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<String> for Literal {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

macro_rules! literal_from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Literal {
            fn from(v: $t) -> Self {
                Self::Number(v.to_string())
            }
        }
    )*};
}
literal_from_unsigned!(u8, u16, u32, u64, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    Not,
    Minus,
    Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryOperator {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    And,
    Or,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Concat,
    RegexMatch,
    RegexIMatch,
    RegexNotMatch,
    RegexNotIMatch,
    /// `->`
    JsonGet,
    /// `->>`
    JsonGetText,
    /// `#>`
    JsonPath,
    /// `#>>`
    JsonPathText,
    /// `@>`
    Contains,
    /// `<@`
    ContainedBy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsTest {
    Null,
    True,
    False,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LikeKind {
    Like,
    ILike,
    SimilarTo,
}

/// The types a value may be cast to. Types that read the catalog (`regclass` and friends) or that run
/// arbitrary input functions are deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataType {
    SmallInt,
    Integer,
    BigInt,
    /// Optional precision, and optional scale when there is a precision.
    Numeric(Option<(u32, Option<i32>)>),
    Real,
    DoublePrecision,
    Text,
    Varchar(Option<u32>),
    Boolean,
    Date,
    Time,
    Timestamp,
    TimestampTz,
    Interval,
    Uuid,
    Json,
    Jsonb,
    Bytea,
}

/// The fields `EXTRACT` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DateField {
    Century,
    Day,
    Decade,
    Dow,
    Doy,
    Epoch,
    Hour,
    Isodow,
    Isoyear,
    Microseconds,
    Millennium,
    Milliseconds,
    Minute,
    Month,
    Quarter,
    Second,
    Week,
    Year,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariadicFunction {
    Coalesce,
    Greatest,
    Least,
}

impl VariadicFunction {
    /// The lower case name, which is what `functions` and `deny_functions` call it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Coalesce => "coalesce",
            Self::Greatest => "greatest",
            Self::Least => "least",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrimSide {
    Both,
    Leading,
    Trailing,
}

/// A call to a function in the catalog. `COALESCE` and the other keyword forms are [`Expr`] variants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Function {
    pub schema: Option<Ident>,
    pub name: Ident,
    pub args: FunctionArgs,
    /// `FILTER (WHERE ...)`
    pub filter: Option<Box<Expr>>,
    pub over: Option<Window>,
}

impl Function {
    /// A plain call `name(args...)` to an unqualified function.
    #[must_use]
    pub fn call(name: Ident, args: Vec<Expr>) -> Self {
        Self {
            schema: None,
            name,
            args: FunctionArgs::List {
                args,
                distinct: false,
                order_by: Vec::new(),
            },
            filter: None,
            over: None,
        }
    }

    /// `schema.name` or just `name`.
    #[must_use]
    pub fn qualified_name(&self) -> String {
        match &self.schema {
            Some(schema) => format!("{schema}.{}", self.name),
            None => self.name.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FunctionArgs {
    /// `f(*)`. Postgres takes neither `DISTINCT` nor `ORDER BY` with it.
    Star,
    List {
        args: Vec<Expr>,
        /// `f(DISTINCT ...)`
        distinct: bool,
        /// `f(... ORDER BY ...)`, for ordered aggregates such as `string_agg`.
        order_by: Vec<SortExpr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Window {
    pub partition_by: Vec<Expr>,
    pub order_by: Vec<SortExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Insert {
    pub table: Table,
    pub columns: Vec<Ident>,
    pub rows: Vec<Vec<Expr>>,
    pub returning: Vec<SelectItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Update {
    pub table: Table,
    pub assignments: Vec<Assignment>,
    pub selection: Option<Expr>,
    pub returning: Vec<SelectItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Assignment {
    pub column: Ident,
    pub value: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Delete {
    pub table: Table,
    pub selection: Option<Expr>,
    pub returning: Vec<SelectItem>,
}

impl From<Literal> for Expr {
    fn from(v: Literal) -> Self {
        Self::Literal(v)
    }
}

impl From<bool> for Expr {
    fn from(v: bool) -> Self {
        Self::Literal(v.into())
    }
}

impl From<&str> for Expr {
    fn from(v: &str) -> Self {
        Self::Literal(v.into())
    }
}

impl From<String> for Expr {
    fn from(v: String) -> Self {
        Self::Literal(v.into())
    }
}

impl From<u64> for Expr {
    fn from(v: u64) -> Self {
        Self::Literal(v.into())
    }
}

impl From<i64> for Expr {
    fn from(v: i64) -> Self {
        let magnitude = Self::Literal(v.unsigned_abs().into());
        if v < 0 {
            Self::Unary {
                op: UnaryOperator::Minus,
                expr: Box::new(magnitude),
            }
        } else {
            magnitude
        }
    }
}

impl From<i32> for Expr {
    fn from(v: i32) -> Self {
        i64::from(v).into()
    }
}

impl From<f64> for Expr {
    /// Finite values become number literals; NaN and the infinities become a cast from text, which is the
    /// only way to write them in SQL.
    fn from(v: f64) -> Self {
        if v.is_finite() {
            // `{:?}` keeps the decimal point (`1.0`, not `1`), which decides integer or numeric arithmetic
            let magnitude = Self::Literal(Literal::Number(format!("{:?}", v.abs())));
            if v.is_sign_negative() && v != 0.0 {
                Self::Unary {
                    op: UnaryOperator::Minus,
                    expr: Box::new(magnitude),
                }
            } else {
                magnitude
            }
        } else {
            let text = if v.is_nan() {
                "NaN"
            } else if v > 0.0 {
                "Infinity"
            } else {
                "-Infinity"
            };
            Self::Cast {
                expr: Box::new(Self::Literal(text.into())),
                data_type: DataType::DoublePrecision,
            }
        }
    }
}
