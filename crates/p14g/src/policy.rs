//! The policy: what untrusted SQL is allowed to do.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ast::{Expr, Ident, Literal, StatementKind},
    backend::{self, Backend, Layout, QuoteIdentifiers, Style},
    check,
    dialect::Dialect,
    error::{Error, Result},
    filter, functions, lower,
};

/// An operator or predicate form that a rule can allow or forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Op {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    And,
    Or,
    Not,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    /// `||`
    Concat,
    Like,
    ILike,
    SimilarTo,
    /// `~`, `~*`, `!~` and `!~*`
    Regex,
    In,
    Between,
    /// `IS [NOT] NULL / TRUE / FALSE / UNKNOWN`
    Is,
    IsDistinctFrom,
    /// `->`, `->>`, `#>` and `#>>`
    Json,
    /// `@>` and `<@`
    Contains,
}

impl Op {
    pub const ALL: &[Self] = &[
        Self::Eq,
        Self::NotEq,
        Self::Lt,
        Self::LtEq,
        Self::Gt,
        Self::GtEq,
        Self::And,
        Self::Or,
        Self::Not,
        Self::Plus,
        Self::Minus,
        Self::Multiply,
        Self::Divide,
        Self::Modulo,
        Self::Concat,
        Self::Like,
        Self::ILike,
        Self::SimilarTo,
        Self::Regex,
        Self::In,
        Self::Between,
        Self::Is,
        Self::IsDistinctFrom,
        Self::Json,
        Self::Contains,
    ];

    /// The SQL spelling, which is also what [`Op::parse`] accepts.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::LtEq => "<=",
            Self::Gt => ">",
            Self::GtEq => ">=",
            Self::And => "and",
            Self::Or => "or",
            Self::Not => "not",
            Self::Plus => "+",
            Self::Minus => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Modulo => "%",
            Self::Concat => "||",
            Self::Like => "like",
            Self::ILike => "ilike",
            Self::SimilarTo => "similar to",
            Self::Regex => "~",
            Self::In => "in",
            Self::Between => "between",
            Self::Is => "is",
            Self::IsDistinctFrom => "is distinct from",
            Self::Json => "->",
            Self::Contains => "@>",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        let lower = s.trim().to_ascii_lowercase();
        if lower == "<>" {
            return Ok(Self::NotEq);
        }
        Self::ALL
            .iter()
            .copied()
            .find(|op| op.as_str() == lower)
            .ok_or_else(|| Error::config(format!("unknown operator {s:?}")))
    }
}

/// A set of [`Op`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct OpSet(u32);

impl OpSet {
    pub fn insert(&mut self, op: Op) {
        self.0 |= 1 << op as u32;
    }

    pub fn contains(self, op: Op) -> bool {
        self.0 & (1 << op as u32) != 0
    }

    /// Everything except regular expression matching, which can be made very slow.
    pub fn default_allowed() -> Self {
        Op::ALL
            .iter()
            .copied()
            .filter(|op| !matches!(op, Op::Regex | Op::SimilarTo))
            .collect()
    }
}

impl FromIterator<Op> for OpSet {
    fn from_iter<T: IntoIterator<Item = Op>>(iter: T) -> Self {
        let mut set = Self::default();
        for op in iter {
            set.insert(op);
        }
        set
    }
}

/// What to do with `*` and `t.*` in a select list or `RETURNING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Star {
    /// Any `*` is an error.
    Reject,
    /// Replace `*` with the columns the matching rule allows. For a rule that allows every column it
    /// becomes `"t".*`.
    #[default]
    Expand,
    /// Leave `*` as it is, and reject it when a table it covers has a rule with a column list, because the
    /// database would return columns the rule does not grant.
    Allow,
}

impl Star {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "reject" => Ok(Self::Reject),
            "expand" => Ok(Self::Expand),
            "allow" => Ok(Self::Allow),
            _ => Err(Error::config(format!("unknown star behaviour {s:?}"))),
        }
    }
}

/// How string literals from the input are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Literals {
    /// Escaped into the SQL text. The connection must use a UTF-8 `client_encoding`.
    #[default]
    Inline,
    /// Replaced by `$n` placeholders, with the values returned in [`SafeSql::params`].
    Params,
}

impl Literals {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "inline" => Ok(Self::Inline),
            "params" => Ok(Self::Params),
            _ => Err(Error::config(format!("unknown literals mode {s:?}"))),
        }
    }
}

/// Bounds on the size and shape of the input, checked before any policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Longest input accepted, in bytes.
    pub max_sql_bytes: usize,
    /// Deepest nesting of expressions and subqueries.
    pub max_depth: usize,
    /// Most expression and clause nodes in one statement.
    pub max_nodes: usize,
    /// Most `JOIN`s (and comma joins) in one statement.
    pub max_joins: usize,
    /// Most subqueries, derived tables and CTEs in one statement.
    pub max_subqueries: usize,
    /// Most `UNION` / `INTERSECT` / `EXCEPT` in one statement.
    pub max_set_operations: usize,
    /// Most items in one `IN (...)` list.
    pub max_in_list: usize,
    /// Most items in one select list or `RETURNING`.
    pub max_projection: usize,
    /// Most rows in one `INSERT ... VALUES`.
    pub max_values_rows: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sql_bytes: 64 * 1024,
            max_depth: 50,
            max_nodes: 10_000,
            max_joins: 8,
            max_subqueries: 16,
            max_set_operations: 8,
            max_in_list: 1_000,
            max_projection: 200,
            max_values_rows: 1_000,
        }
    }
}

/// Allows reading from a table or view.
///
/// Reads include every mention of a column, wherever it appears: a column used in a `WHERE` or
/// `ORDER BY`, or in the `WHERE` of an `UPDATE`, has been read just as much as one in the select list.
pub struct Select<C = ()> {
    table: String,
    columns: Option<Vec<String>>,
    only: bool,
    filter: Option<Box<FilterFn<C>>>,
}

impl<C> Select<C> {
    /// `table` is `name` or `schema.name`, spelled exactly as Postgres stores it.
    pub fn table(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            columns: None,
            only: false,
            filter: None,
        }
    }

    /// Restrict the rule to these columns. Without this, every column is allowed.
    #[must_use]
    pub fn columns<S: Into<String>>(mut self, columns: impl IntoIterator<Item = S>) -> Self {
        self.columns = Some(columns.into_iter().map(Into::into).collect());
        self
    }

    /// Write the table as `ONLY table`, so that rows of its inheritance children are left out.
    ///
    /// In Postgres a query on a table also reads, updates and deletes the rows of tables that inherit from
    /// it, checking privileges on the parent alone. Set this when the table has children the policy should
    /// not reach. Do not set it for a partitioned table: the parent holds no rows of its own.
    ///
    /// Every `Select`, `Update` and `Delete` rule for one table must agree on this.
    #[must_use]
    pub fn only(mut self, only: bool) -> Self {
        self.only = only;
        self
    }

    /// A condition every row read through this rule has to meet, computed from the context passed to
    /// `rewrite`.
    ///
    /// The table is replaced in the statement by a subquery with the condition as its `WHERE`, so it holds
    /// through joins and subqueries. The condition is p14g's to write: it may use columns and functions
    /// the rule does not otherwise allow.
    ///
    /// Postgres may evaluate the statement's own conditions on a row before this one, so an error such as
    /// a division by zero can reveal something about rows the filter excludes. Row-level security or a
    /// `security_barrier` view does not have that gap.
    #[must_use]
    pub fn filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Filter + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(move |ctx| Ok(filter(ctx))));
        self
    }

    /// Like [`Select::filter`] for a callback that can fail.
    #[must_use]
    pub fn try_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Result<Filter> + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(filter));
        self
    }
}

/// A condition for a rule's `filter`: an SQL expression and the values for its `:name` placeholders.
///
/// The expression is parsed by p14g, never pasted into the output, and each value is written as an
/// escaped literal (or a parameter, with [`Literals::Params`]). A list is allowed where the placeholder is
/// the only item of an `IN (...)`. Subqueries are not allowed.
///
/// ```
/// use p14g::Filter;
///
/// let filter = Filter::new("org = :org and status in (:statuses)")
///     .bind("org", 42)
///     .bind("statuses", vec!["open", "held"]);
/// ```
#[derive(Debug, Clone)]
pub struct Filter {
    pub(crate) sql: String,
    pub(crate) values: Vec<(String, FilterValue)>,
}

impl Filter {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            values: Vec::new(),
        }
    }

    /// Give the value for `:name`. Names are letters, digits and underscores, and match exactly.
    #[must_use]
    pub fn bind(mut self, name: impl Into<String>, value: impl Into<FilterValue>) -> Self {
        self.values.push((name.into(), value.into()));
        self
    }
}

/// A value bound to a placeholder of a [`Filter`]: one value, or a list for `IN (:name)`.
#[derive(Debug, Clone)]
pub enum FilterValue {
    One(Expr),
    Many(Vec<Expr>),
}

impl<T: Into<Expr>> From<Vec<T>> for FilterValue {
    fn from(values: Vec<T>) -> Self {
        Self::Many(values.into_iter().map(Into::into).collect())
    }
}

macro_rules! filter_value_from {
    ($($t:ty),*) => {$(
        impl From<$t> for FilterValue {
            fn from(value: $t) -> Self {
                Self::One(value.into())
            }
        }
    )*};
}
filter_value_from!(Expr, Literal, bool, i32, i64, u64, f64, &str, String);

pub(crate) type FilterFn<C> = dyn Fn(&C) -> Result<Filter> + Send + Sync;

/// Columns a rule sets on every inserted row.
type ExtraFn<C> = dyn Fn(&C) -> Result<Vec<(String, Expr)>> + Send + Sync;

/// Allows `INSERT INTO table (columns) VALUES ...`.
pub struct Insert<C = ()> {
    table: String,
    columns: Option<Vec<String>>,
    extra: Option<Box<ExtraFn<C>>>,
}

impl<C> Insert<C> {
    pub fn table(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            columns: None,
            extra: None,
        }
    }

    /// Restrict the columns the statement may set. Without this, any column may be set.
    #[must_use]
    pub fn columns<S: Into<String>>(mut self, columns: impl IntoIterator<Item = S>) -> Self {
        self.columns = Some(columns.into_iter().map(Into::into).collect());
        self
    }

    /// Columns p14g adds to every inserted row, computed from the context passed to `rewrite`.
    ///
    /// A statement that sets one of these columns itself is rejected.
    #[must_use]
    pub fn extra<F, I, S, V>(mut self, extra: F) -> Self
    where
        F: Fn(&C) -> I + Send + Sync + 'static,
        I: IntoIterator<Item = (S, V)>,
        S: Into<String>,
        V: Into<Expr>,
    {
        self.extra = Some(Box::new(move |ctx| {
            Ok(extra(ctx).into_iter().map(|(k, v)| (k.into(), v.into())).collect())
        }));
        self
    }

    /// Like [`Insert::extra`] for a callback that can fail.
    #[must_use]
    pub fn try_extra<F>(mut self, extra: F) -> Self
    where
        F: Fn(&C) -> Result<Vec<(String, Expr)>> + Send + Sync + 'static,
    {
        self.extra = Some(Box::new(extra));
        self
    }
}

/// Allows `UPDATE table SET column = ...`.
pub struct Update<C = ()> {
    table: String,
    columns: Option<Vec<String>>,
    allow_unfiltered: bool,
    only: bool,
    filter: Option<Box<FilterFn<C>>>,
}

impl<C> Update<C> {
    pub fn table(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            columns: None,
            allow_unfiltered: false,
            only: false,
            filter: None,
        }
    }

    /// Restrict the columns the statement may set. Without this, any column may be set.
    #[must_use]
    pub fn columns<S: Into<String>>(mut self, columns: impl IntoIterator<Item = S>) -> Self {
        self.columns = Some(columns.into_iter().map(Into::into).collect());
        self
    }

    /// Allow an `UPDATE` with no `WHERE` clause.
    ///
    /// Rejecting those catches mistakes, it is not a security control: `WHERE true` passes.
    #[must_use]
    pub fn allow_unfiltered(mut self, allow: bool) -> Self {
        self.allow_unfiltered = allow;
        self
    }

    /// Write the table as `ONLY table`. See [`Select::only`].
    #[must_use]
    pub fn only(mut self, only: bool) -> Self {
        self.only = only;
        self
    }

    /// A condition every row this rule lets a statement update has to meet, computed from the context passed
    /// to `rewrite`. It is added to the statement's `WHERE` with `AND`. A statement that sets a column the
    /// condition uses is rejected, so a row cannot be moved out of it. See [`Select::filter`].
    #[must_use]
    pub fn filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Filter + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(move |ctx| Ok(filter(ctx))));
        self
    }

    /// Like `filter` for a callback that can fail.
    #[must_use]
    pub fn try_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Result<Filter> + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(filter));
        self
    }
}

/// Allows `DELETE FROM table`.
pub struct Delete<C = ()> {
    table: String,
    allow_unfiltered: bool,
    only: bool,
    filter: Option<Box<FilterFn<C>>>,
}

impl<C> Delete<C> {
    pub fn table(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            allow_unfiltered: false,
            only: false,
            filter: None,
        }
    }

    /// Allow a `DELETE` with no `WHERE` clause. See [`Update::allow_unfiltered`].
    #[must_use]
    pub fn allow_unfiltered(mut self, allow: bool) -> Self {
        self.allow_unfiltered = allow;
        self
    }

    /// Write the table as `ONLY table`. See [`Select::only`].
    #[must_use]
    pub fn only(mut self, only: bool) -> Self {
        self.only = only;
        self
    }

    /// A condition every row this rule lets a statement delete has to meet, computed from the context passed
    /// to `rewrite`. It is added to the statement's `WHERE` with `AND`. See [`Select::filter`].
    #[must_use]
    pub fn filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Filter + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(move |ctx| Ok(filter(ctx))));
        self
    }

    /// Like `filter` for a callback that can fail.
    #[must_use]
    pub fn try_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&C) -> Result<Filter> + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(filter));
        self
    }
}

/// `schema.name` or `name`, as written in a rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TableKey {
    pub schema: Option<Ident>,
    pub name: Ident,
}

impl TableKey {
    fn parse(table: &str) -> Result<Self> {
        let invalid = |e: Error| Error::config(format!("invalid table name {table:?}: {}", e.message()));
        let mut parts = table.split('.');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(name), None, None) => Ok(Self {
                schema: None,
                name: Ident::new(name).map_err(invalid)?,
            }),
            (Some(schema), Some(name), None) => Ok(Self {
                schema: Some(Ident::new(schema).map_err(invalid)?),
                name: Ident::new(name).map_err(invalid)?,
            }),
            _ => Err(Error::config(format!(
                "invalid table name {table:?}: expected `name` or `schema.name`"
            ))),
        }
    }
}

/// A column list in the order the rule gave it, which is the order `*` expands to.
fn parse_columns(columns: Option<Vec<String>>, table: &str) -> Result<Option<Vec<Ident>>> {
    let Some(columns) = columns else { return Ok(None) };
    let mut out = Vec::with_capacity(columns.len());
    for column in columns {
        let ident = Ident::new(column.as_str()).map_err(|e| {
            Error::config(format!(
                "invalid column {column:?} for table {table:?}: {}",
                e.message()
            ))
        })?;
        if out.contains(&ident) {
            return Err(Error::config(format!(
                "duplicate column {column:?} for table {table:?}"
            )));
        }
        out.push(ident);
    }
    Ok(Some(out))
}

pub(crate) struct SelectRule<C> {
    pub columns: Option<Vec<Ident>>,
    pub filter: Option<Box<FilterFn<C>>>,
}

pub(crate) struct InsertRule<C> {
    pub columns: Option<Vec<Ident>>,
    pub extra: Option<Box<ExtraFn<C>>>,
}

pub(crate) struct UpdateRule<C> {
    pub columns: Option<Vec<Ident>>,
    pub allow_unfiltered: bool,
    pub filter: Option<Box<FilterFn<C>>>,
}

pub(crate) struct DeleteRule<C> {
    pub allow_unfiltered: bool,
    pub filter: Option<Box<FilterFn<C>>>,
}

/// Builds a [`Policy`]. Nothing is validated until [`PolicyBuilder::build`].
pub struct PolicyBuilder<C = ()> {
    selects: Vec<Select<C>>,
    inserts: Vec<Insert<C>>,
    updates: Vec<Update<C>>,
    deletes: Vec<Delete<C>>,
    functions: Vec<String>,
    deny_functions: Vec<String>,
    default_functions: bool,
    operators: Option<Vec<Op>>,
    star: Star,
    literals: Literals,
    quote_identifiers: QuoteIdentifiers,
    layout: Layout,
    qualify_builtins: bool,
    limits: Limits,
    max_rows: Option<u64>,
    default_schema: Option<String>,
    dialect: Dialect,
    backend: Backend,
}

impl<C> Default for PolicyBuilder<C> {
    fn default() -> Self {
        Self {
            selects: Vec::new(),
            inserts: Vec::new(),
            updates: Vec::new(),
            deletes: Vec::new(),
            functions: Vec::new(),
            deny_functions: Vec::new(),
            default_functions: true,
            operators: None,
            star: Star::default(),
            literals: Literals::default(),
            quote_identifiers: QuoteIdentifiers::default(),
            layout: Layout::default(),
            qualify_builtins: false,
            limits: Limits::default(),
            max_rows: None,
            default_schema: None,
            dialect: Dialect::default(),
            backend: Backend::default(),
        }
    }
}

impl<C> PolicyBuilder<C> {
    #[must_use]
    pub fn select(mut self, rule: Select<C>) -> Self {
        self.selects.push(rule);
        self
    }

    #[must_use]
    pub fn insert(mut self, rule: Insert<C>) -> Self {
        self.inserts.push(rule);
        self
    }

    #[must_use]
    pub fn update(mut self, rule: Update<C>) -> Self {
        self.updates.push(rule);
        self
    }

    #[must_use]
    pub fn delete(mut self, rule: Delete<C>) -> Self {
        self.deletes.push(rule);
        self
    }

    /// Allow more functions, by `name` or `schema.name`, on top of the defaults.
    #[must_use]
    pub fn functions<S: Into<String>>(mut self, functions: impl IntoIterator<Item = S>) -> Self {
        self.functions.extend(functions.into_iter().map(Into::into));
        self
    }

    /// Forbid functions that would otherwise be allowed. Naming one that is not allowed is an error.
    #[must_use]
    pub fn deny_functions<S: Into<String>>(mut self, functions: impl IntoIterator<Item = S>) -> Self {
        self.deny_functions.extend(functions.into_iter().map(Into::into));
        self
    }

    /// Whether to start from the built-in set in [`functions`](crate::functions). On by default.
    #[must_use]
    pub fn default_functions(mut self, enabled: bool) -> Self {
        self.default_functions = enabled;
        self
    }

    /// The operators a statement may use, on any table and on none.
    ///
    /// The default is every operator except regular expression matching (`~` and `SIMILAR TO`).
    #[must_use]
    pub fn operators(mut self, operators: impl IntoIterator<Item = Op>) -> Self {
        self.operators = Some(operators.into_iter().collect());
        self
    }

    #[must_use]
    pub fn star_behaviour(mut self, star: Star) -> Self {
        self.star = star;
        self
    }

    #[must_use]
    pub fn literals(mut self, literals: Literals) -> Self {
        self.literals = literals;
        self
    }

    /// Which identifiers are written in double quotes. The default is only the ones that need it.
    #[must_use]
    pub fn quote_identifiers(mut self, quote_identifiers: QuoteIdentifiers) -> Self {
        self.quote_identifiers = quote_identifiers;
        self
    }

    /// Whether each clause of the output goes on its own line, the default, or everything on one.
    #[must_use]
    pub fn layout(mut self, layout: Layout) -> Self {
        self.layout = layout;
        self
    }

    /// Write the default functions as `pg_catalog.name(...)`. Off by default.
    ///
    /// Postgres looks in `pg_catalog` first, but among functions with different argument types it picks the
    /// best match wherever it is in the `search_path`. Turn this on if the role's `search_path` has a schema
    /// that people you do not trust can create functions in.
    #[must_use]
    pub fn qualify_builtins(mut self, qualify_builtins: bool) -> Self {
        self.qualify_builtins = qualify_builtins;
        self
    }

    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Cap the rows a `SELECT` returns: a missing `LIMIT` is added and a larger one is reduced.
    #[must_use]
    pub fn max_rows(mut self, max_rows: Option<u64>) -> Self {
        self.max_rows = max_rows;
        self
    }

    /// The schema that unqualified table names belong to, in rules and in statements.
    ///
    /// Without this an unqualified name is written unqualified and Postgres resolves it through the
    /// `search_path`, where a table of the same name in an earlier schema, or a temporary table, is found
    /// first. With it `orders` is always written `"schema"."orders"`.
    #[must_use]
    pub fn default_schema(mut self, schema: impl Into<String>) -> Self {
        self.default_schema = Some(schema.into());
        self
    }

    #[must_use]
    pub fn dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    #[must_use]
    pub fn backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    pub fn build(self) -> Result<Policy<C>> {
        let operators = self
            .operators
            .map_or_else(OpSet::default_allowed, |ops| ops.into_iter().collect());

        let default_schema = self
            .default_schema
            .map(|schema| {
                Ident::new(schema.as_str())
                    .map_err(|e| Error::config(format!("invalid default schema {schema:?}: {}", e.message())))
            })
            .transpose()?;
        let table_key = |table: &str| {
            TableKey::parse(table).map(|key| TableKey {
                schema: key.schema.or_else(|| default_schema.clone()),
                name: key.name,
            })
        };

        // `only` is a property of the table, so every rule that reads or writes its rows has to agree
        let mut only: BTreeMap<TableKey, bool> = BTreeMap::new();
        let mut agree = |key: &TableKey, table: &str, rule_only: bool| match only.insert(key.clone(), rule_only) {
            Some(previous) if previous != rule_only => Err(Error::config(format!(
                "the rules for table {table:?} disagree about `only`"
            ))),
            _ => Ok(()),
        };

        let mut selects: BTreeMap<TableKey, Vec<SelectRule<C>>> = BTreeMap::new();
        for rule in self.selects {
            let key = table_key(&rule.table)?;
            agree(&key, &rule.table, rule.only)?;
            let columns = parse_columns(rule.columns, &rule.table)?;
            selects.entry(key).or_default().push(SelectRule {
                columns,
                filter: rule.filter,
            });
        }
        let mut inserts: BTreeMap<TableKey, Vec<InsertRule<C>>> = BTreeMap::new();
        for rule in self.inserts {
            let key = table_key(&rule.table)?;
            let columns = parse_columns(rule.columns, &rule.table)?;
            inserts.entry(key).or_default().push(InsertRule {
                columns,
                extra: rule.extra,
            });
        }
        let mut updates: BTreeMap<TableKey, Vec<UpdateRule<C>>> = BTreeMap::new();
        for rule in self.updates {
            let key = table_key(&rule.table)?;
            agree(&key, &rule.table, rule.only)?;
            let columns = parse_columns(rule.columns, &rule.table)?;
            updates.entry(key).or_default().push(UpdateRule {
                columns,
                allow_unfiltered: rule.allow_unfiltered,
                filter: rule.filter,
            });
        }
        let mut deletes: BTreeMap<TableKey, DeleteRule<C>> = BTreeMap::new();
        for rule in self.deletes {
            let key = table_key(&rule.table)?;
            agree(&key, &rule.table, rule.only)?;
            // a delete rule has nothing for a statement to fit or not, so there is nothing to choose between
            let previous = deletes.insert(
                key,
                DeleteRule {
                    allow_unfiltered: rule.allow_unfiltered,
                    filter: rule.filter,
                },
            );
            if previous.is_some() {
                return Err(Error::config(format!(
                    "there is more than one delete rule for table {:?}",
                    rule.table
                )));
            }
        }

        let mut allowed: BTreeSet<String> = BTreeSet::new();
        if self.default_functions {
            allowed.extend(functions::defaults().map(str::to_owned));
        }
        for function in self.functions {
            allowed.insert(function_key(&function)?);
        }
        for function in self.deny_functions {
            let key = function_key(&function)?;
            if !allowed.remove(&key) {
                return Err(Error::config(format!(
                    "cannot deny function {function:?}: it is not an allowed function"
                )));
            }
        }

        if self.limits.max_depth == 0 {
            return Err(Error::config("limits.max_depth must be at least 1"));
        }

        let only = only.into_iter().filter_map(|(key, only)| only.then_some(key)).collect();

        Ok(Policy {
            only,
            selects,
            inserts,
            updates,
            deletes,
            functions: allowed,
            operators,
            star: self.star,
            literals: self.literals,
            quote_identifiers: self.quote_identifiers,
            layout: self.layout,
            qualify_builtins: self.qualify_builtins,
            limits: self.limits,
            max_rows: self.max_rows,
            default_schema: default_schema.clone(),
            dialect: self.dialect,
            backend: self.backend,
        })
    }
}

/// Normalise a function name from the configuration to the key used for lookups: `name` or `schema.name`,
/// with a `pg_catalog.` prefix dropped.
fn function_key(function: &str) -> Result<String> {
    let invalid = |e: Error| Error::config(format!("invalid function name {function:?}: {}", e.message()));
    let mut parts = function.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(name), None, None) => Ok(Ident::new(name).map_err(invalid)?.to_string()),
        (Some(schema), Some(name), None) => {
            let schema = Ident::new(schema).map_err(invalid)?;
            let name = Ident::new(name).map_err(invalid)?;
            Ok(function_lookup_key(Some(&schema), &name))
        }
        _ => Err(Error::config(format!(
            "invalid function name {function:?}: expected `name` or `schema.name`"
        ))),
    }
}

pub(crate) fn function_lookup_key(schema: Option<&Ident>, name: &Ident) -> String {
    match schema {
        Some(schema) if schema.as_str() != "pg_catalog" => format!("{schema}.{name}"),
        _ => name.to_string(),
    }
}

/// The SQL to run, and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSql {
    /// SQL that is safe to send to the database.
    pub sql: String,
    /// Values for the placeholders p14g added, in order. Empty with [`Literals::Inline`].
    ///
    /// The first one is numbered one above the highest placeholder in the input, so append these to the
    /// parameters the input already needed.
    pub params: Vec<String>,
    pub kind: StatementKind,
    /// The tables and views the statement uses, as named in the input, sorted.
    pub tables: Vec<String>,
}

/// A compiled set of rules. Build one with [`Policy::builder`] and reuse it for every statement.
///
/// `C` is the type of the context value passed to [`Policy::rewrite`] and handed on to `filter` and
/// [`Insert::extra`] callbacks.
pub struct Policy<C = ()> {
    /// Tables that are always written `ONLY table`.
    pub(crate) only: BTreeSet<TableKey>,
    pub(crate) selects: BTreeMap<TableKey, Vec<SelectRule<C>>>,
    pub(crate) inserts: BTreeMap<TableKey, Vec<InsertRule<C>>>,
    pub(crate) updates: BTreeMap<TableKey, Vec<UpdateRule<C>>>,
    pub(crate) deletes: BTreeMap<TableKey, DeleteRule<C>>,
    pub(crate) functions: BTreeSet<String>,
    pub(crate) operators: OpSet,
    pub(crate) star: Star,
    literals: Literals,
    quote_identifiers: QuoteIdentifiers,
    layout: Layout,
    qualify_builtins: bool,
    pub(crate) limits: Limits,
    max_rows: Option<u64>,
    /// The schema unqualified table names are given before they are looked up and written.
    pub(crate) default_schema: Option<Ident>,
    dialect: Dialect,
    backend: Backend,
}

impl<C> Policy<C> {
    #[must_use]
    pub fn builder() -> PolicyBuilder<C> {
        PolicyBuilder::default()
    }

    /// The `GRANT` statements that give `role` the table access this policy allows.
    ///
    /// Run them once as the owner of the tables, for the role that will run p14g's output, so that the
    /// database enforces the same rules. `context` is passed to [`Insert::extra`] and `filter` callbacks to
    /// learn which columns they use.
    ///
    /// Grants cannot say everything a policy does, so they allow somewhat more:
    ///
    /// * several rules for one table are alternatives in the policy, here their columns are combined;
    /// * functions, operators and cast types are not restricted;
    /// * `only` has no equivalent, a grant on a parent table always covers its children's rows;
    /// * a `filter` has no equivalent either: the grants let the role read and write every row.
    ///
    /// Not included: `USAGE` on sequences that inserted rows take defaults from.
    pub fn grants(&self, role: &str, context: &C) -> Result<Vec<String>> {
        #[derive(Default)]
        struct Columns {
            all: bool,
            listed: Vec<Ident>,
        }

        impl Columns {
            fn add(&mut self, columns: Option<&[Ident]>) {
                match columns {
                    None => self.all = true,
                    Some(columns) => {
                        for column in columns {
                            if !self.listed.contains(column) {
                                self.listed.push(column.clone());
                            }
                        }
                    }
                }
            }
        }

        let quote = |ident: &Ident| backend::quote_ident(self.backend, ident);
        let role = Ident::new(role).map_err(|e| Error::config(format!("invalid role {role:?}: {}", e.message())))?;
        let role = quote(&role);
        let table_name = |key: &TableKey| match &key.schema {
            Some(schema) => format!("{}.{}", quote(schema), quote(&key.name)),
            None => quote(&key.name),
        };

        // a filter reads the columns it names, which takes the SELECT privilege on them whatever the statement
        let filter_columns = |key: &TableKey, filter: Option<&FilterFn<C>>| -> Result<Vec<Ident>> {
            let Some(filter) = filter else {
                return Ok(Vec::new());
            };
            let bound = filter::bind(&filter(context)?, &key.name, &key.name, &self.limits)?;
            Ok(bound.columns.into_iter().collect())
        };

        let mut tables: BTreeMap<&TableKey, [Columns; 3]> = BTreeMap::new();
        for (key, rules) in &self.selects {
            for rule in rules {
                let columns = &mut tables.entry(key).or_default()[0];
                columns.add(rule.columns.as_deref());
                columns.add(Some(&filter_columns(key, rule.filter.as_deref())?));
            }
        }
        for (key, rules) in &self.inserts {
            for rule in rules {
                let columns = &mut tables.entry(key).or_default()[1];
                columns.add(rule.columns.as_deref());
                if let Some(extra) = &rule.extra {
                    for (column, _) in extra(context)? {
                        let column = Ident::new(column.as_str()).map_err(|e| {
                            Error::callback(format!("extra returned an invalid column {column:?}: {}", e.message()))
                        })?;
                        columns.add(Some(&[column]));
                    }
                }
            }
        }
        for (key, rules) in &self.updates {
            for rule in rules {
                let [select, _, update] = tables.entry(key).or_default();
                update.add(rule.columns.as_deref());
                select.add(Some(&filter_columns(key, rule.filter.as_deref())?));
            }
        }
        for (key, rule) in &self.deletes {
            let [select, ..] = tables.entry(key).or_default();
            select.add(Some(&filter_columns(key, rule.filter.as_deref())?));
        }

        let mut statements = Vec::new();
        let schemas: BTreeSet<&Ident> = tables.keys().filter_map(|key| key.schema.as_ref()).collect();
        for schema in schemas {
            statements.push(format!("GRANT USAGE ON SCHEMA {} TO {role}", quote(schema)));
        }
        for (key, columns) in &tables {
            let table = table_name(key);
            for (privilege, columns) in ["SELECT", "INSERT", "UPDATE"].into_iter().zip(columns) {
                if columns.all {
                    statements.push(format!("GRANT {privilege} ON {table} TO {role}"));
                } else if !columns.listed.is_empty() {
                    let list = columns.listed.iter().map(&quote).collect::<Vec<_>>().join(", ");
                    statements.push(format!("GRANT {privilege} ({list}) ON {table} TO {role}"));
                }
            }
            if self.deletes.contains_key(*key) {
                statements.push(format!("GRANT DELETE ON {table} TO {role}"));
            }
        }
        Ok(statements)
    }

    /// Check one SQL statement against the policy and return it rewritten so it is safe to run.
    pub fn rewrite(&self, sql: &str, context: &C) -> Result<SafeSql> {
        self.rewrite_kinds(sql, context, None)
    }

    /// Like [`Policy::rewrite`], and also rejects the statement unless its kind is in `allow`.
    pub fn rewrite_kinds(&self, sql: &str, context: &C, allow: Option<&[StatementKind]>) -> Result<SafeSql> {
        let lowered = lower::parse(sql, self.dialect, &self.limits)?;
        let mut statement = lowered.statement;
        let kind = statement.kind();
        if let Some(allow) = allow
            && !allow.contains(&kind)
        {
            return Err(Error::denied(format!(
                "{} statements are not allowed here",
                kind.as_str().to_uppercase()
            )));
        }
        let tables = check::check(self, &mut statement, context)?;
        if let Some(max_rows) = self.max_rows {
            check::apply_max_rows(&mut statement, max_rows)?;
        }
        let style = Style {
            literals: self.literals,
            quote: self.quote_identifiers,
            layout: self.layout,
            qualify_builtins: self.qualify_builtins,
        };
        let written = backend::write(self.backend, &statement, style, lowered.max_placeholder)?;
        Ok(SafeSql {
            sql: written.sql,
            params: written.params,
            kind,
            tables,
        })
    }
}
