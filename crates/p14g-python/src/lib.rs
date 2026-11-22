//! Python bindings for p14g.

use p14g::{ErrorKind, Literals, Op, PolicyBuilder, Star, StatementKind, ast, functions};
use pyo3::{
    create_exception,
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    sync::PyOnceLock,
    types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple, PyType},
};

/// The context handed to `rewrite()`, passed on untouched to `filter` and `extra` callables.
type Context = Py<PyAny>;
type Policy = p14g::Policy<Context>;

create_exception!(
    p14g,
    P14gError,
    PyValueError,
    "A statement was rejected, or a policy could not be built.

`kind` is one of 'parse', 'unsupported', 'denied', 'limit', 'config' or 'callback'. `message` is the text
without the position, and `line` and `column` give the position in the SQL when it is known."
);

/// Convert a p14g error, keeping the exception a callback raised as its cause.
fn to_py_err(py: Python<'_>, mut error: p14g::Error) -> PyErr {
    let cause = error.take_source().and_then(|source| source.downcast::<PyErr>().ok());
    let err = P14gError::new_err(error.to_string());
    let value = err.value(py);
    let location = error.location();
    // setting attributes on a new exception instance does not fail
    let _ = value.setattr("kind", error.kind().as_str());
    let _ = value.setattr("message", error.message());
    let _ = value.setattr("line", location.map(|l| l.line));
    let _ = value.setattr("column", location.map(|l| l.column));
    if let Some(cause) = cause {
        err.set_cause(py, Some(*cause));
    }
    err
}

/// An error raised inside a callback, to be carried through p14g and raised again as the cause.
fn callback_error(error: PyErr) -> p14g::Error {
    p14g::Error::callback_source(error)
}

fn repr_list(items: Option<&Vec<String>>) -> String {
    items.map_or_else(|| "None".to_owned(), |items| format!("{items:?}"))
}

/// A `types.GenericAlias` for `cls[item]`, so the generic classes in `p14g.pyi` can be subscripted.
fn generic_alias<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    static GENERIC_ALIAS: PyOnceLock<Py<PyType>> = PyOnceLock::new();
    GENERIC_ALIAS
        .import(cls.py(), "types", "GenericAlias")?
        .call1((cls, item))
}

// ------------------------------------------------------------------ rules

/// Allows reading from a table or view.
///
/// Every mention of a column counts as a read, wherever it is: in the select list, in a `WHERE` or
/// `ORDER BY`, or in the `WHERE` of an `UPDATE`.
#[pyclass(frozen, module = "p14g", name = "Select")]
struct PySelect {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    #[pyo3(get)]
    only: bool,
    filter: Option<Py<PyAny>>,
}

#[pymethods]
impl PySelect {
    /// `Select[C]` in an annotation. The context type is for type checkers; nothing checks it at run time.
    #[classmethod]
    fn __class_getitem__<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        generic_alias(cls, item)
    }

    #[new]
    #[pyo3(signature = (table, *, columns=None, only=false, filter=None))]
    fn new(
        py: Python<'_>,
        table: String,
        columns: Option<Vec<String>>,
        only: bool,
        filter: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        check_filter(py, filter.as_ref())?;
        Ok(Self {
            table,
            columns,
            only,
            filter,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Select({:?}, columns={}, only={})",
            self.table,
            repr_list(self.columns.as_ref()),
            repr_bool(self.only)
        )
    }
}

fn repr_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// A rule's `filter` is a callable, or a string for a condition with no values to bind.
fn check_filter(py: Python<'_>, filter: Option<&Py<PyAny>>) -> PyResult<()> {
    match filter.map(|filter| filter.bind(py)) {
        Some(filter) if !filter.is_callable() && !filter.is_instance_of::<PyString>() => Err(PyTypeError::new_err(
            "filter must be a callable returning (sql, values), or a str",
        )),
        _ => Ok(()),
    }
}

/// Call a rule's `filter` with the context and read what it returns: `(sql, values)` or just `sql`.
fn python_filter(filter: &Py<PyAny>, context: &Context) -> p14g::Result<p14g::Filter> {
    Python::attach(|py| {
        let filter = filter.bind(py);
        let returned = if filter.is_callable() {
            filter.call1((context.bind(py),))?
        } else {
            filter.clone()
        };
        if let Ok(sql) = returned.cast::<PyString>() {
            return Ok(p14g::Filter::new(sql.to_str()?));
        }
        let invalid = || PyTypeError::new_err("a filter must return (sql, values) or sql");
        let (sql, values): (Bound<'_, PyString>, Bound<'_, PyDict>) = returned.extract().map_err(|_| invalid())?;
        let mut filter = p14g::Filter::new(sql.to_str()?);
        for (name, value) in values.iter() {
            let name: String = name
                .extract()
                .map_err(|_| PyTypeError::new_err("the keys of a filter's values must be placeholder names"))?;
            // a list is the items of `IN (:name)`, anything else is one value
            let value = if value.is_instance_of::<PyList>() {
                let items: Vec<Bound<'_, PyAny>> = value.extract()?;
                p14g::FilterValue::Many(items.iter().map(py_to_expr).collect::<PyResult<_>>()?)
            } else {
                p14g::FilterValue::One(py_to_expr(&value)?)
            };
            filter = filter.bind(name, value);
        }
        Ok(filter)
    })
    .map_err(callback_error)
}

fn parse_operators(py: Python<'_>, operators: &[String]) -> PyResult<Vec<Op>> {
    operators
        .iter()
        .map(|op| Op::parse(op).map_err(|e| to_py_err(py, e)))
        .collect()
}

/// The `extra` of an insert rule: nothing, fixed values, or a callable to ask each time.
enum Extra {
    None,
    Fixed(Vec<(String, ast::Expr)>),
    Callable(Py<PyAny>),
}

/// Allows `INSERT INTO table (columns) VALUES ...`.
///
/// `extra` gives columns p14g sets on every inserted row: a dict, or a callable that takes the context
/// passed to `rewrite()` and returns a dict. A statement that sets one of those columns itself is rejected.
#[pyclass(frozen, module = "p14g", name = "Insert")]
struct PyInsert {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    extra: Extra,
}

#[pymethods]
impl PyInsert {
    /// `Insert[C]` in an annotation. The context type is for type checkers; nothing checks it at run time.
    #[classmethod]
    fn __class_getitem__<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        generic_alias(cls, item)
    }

    #[new]
    #[pyo3(signature = (table, *, columns=None, extra=None))]
    fn new(table: String, columns: Option<Vec<String>>, extra: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let extra = match extra {
            None => Extra::None,
            Some(extra) if extra.is_callable() => Extra::Callable(extra.clone().unbind()),
            Some(extra) => Extra::Fixed(extra_values(extra)?),
        };
        Ok(Self { table, columns, extra })
    }

    fn __repr__(&self) -> String {
        format!("Insert({:?}, columns={})", self.table, repr_list(self.columns.as_ref()))
    }
}

/// Read the `{column: value}` dict of an insert rule's `extra`.
fn extra_values(extra: &Bound<'_, PyAny>) -> PyResult<Vec<(String, ast::Expr)>> {
    let dict = extra
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("extra must be a dict or a callable returning a dict"))?;
    dict.iter()
        .map(|(column, value)| {
            let column: String = column
                .extract()
                .map_err(|_| PyTypeError::new_err("the keys of extra must be column names"))?;
            Ok((column, py_to_expr(&value)?))
        })
        .collect()
}

/// Allows `UPDATE table SET column = ...` for the listed columns.
///
/// An `UPDATE` with no `WHERE` is rejected unless `allow_unfiltered` is set. That catches mistakes, it is
/// not a security control: `WHERE true` passes.
#[pyclass(frozen, module = "p14g", name = "Update")]
struct PyUpdate {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    #[pyo3(get)]
    allow_unfiltered: bool,
    #[pyo3(get)]
    only: bool,
    filter: Option<Py<PyAny>>,
}

#[pymethods]
impl PyUpdate {
    /// `Update[C]` in an annotation. The context type is for type checkers; nothing checks it at run time.
    #[classmethod]
    fn __class_getitem__<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        generic_alias(cls, item)
    }

    #[new]
    #[pyo3(signature = (table, *, columns=None, allow_unfiltered=false, only=false, filter=None))]
    fn new(
        py: Python<'_>,
        table: String,
        columns: Option<Vec<String>>,
        allow_unfiltered: bool,
        only: bool,
        filter: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        check_filter(py, filter.as_ref())?;
        Ok(Self {
            table,
            columns,
            allow_unfiltered,
            only,
            filter,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Update({:?}, columns={}, allow_unfiltered={}, only={})",
            self.table,
            repr_list(self.columns.as_ref()),
            repr_bool(self.allow_unfiltered),
            repr_bool(self.only)
        )
    }
}

/// Allows `DELETE FROM table`. A `DELETE` with no `WHERE` is rejected unless `allow_unfiltered` is set.
#[pyclass(frozen, module = "p14g", name = "Delete")]
struct PyDelete {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    allow_unfiltered: bool,
    #[pyo3(get)]
    only: bool,
    filter: Option<Py<PyAny>>,
}

#[pymethods]
impl PyDelete {
    /// `Delete[C]` in an annotation. The context type is for type checkers; nothing checks it at run time.
    #[classmethod]
    fn __class_getitem__<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        generic_alias(cls, item)
    }

    #[new]
    #[pyo3(signature = (table, *, allow_unfiltered=false, only=false, filter=None))]
    fn new(
        py: Python<'_>,
        table: String,
        allow_unfiltered: bool,
        only: bool,
        filter: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        check_filter(py, filter.as_ref())?;
        Ok(Self {
            table,
            allow_unfiltered,
            only,
            filter,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Delete({:?}, allow_unfiltered={}, only={})",
            self.table,
            repr_bool(self.allow_unfiltered),
            repr_bool(self.only)
        )
    }
}

/// Bounds on the size and shape of a statement, checked before any rule.
#[pyclass(frozen, module = "p14g", name = "Limits", get_all)]
#[expect(clippy::struct_field_names, reason = "the names are the Python keyword arguments")]
struct PyLimits {
    max_sql_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_joins: usize,
    max_subqueries: usize,
    max_set_operations: usize,
    max_in_list: usize,
    max_projection: usize,
    max_values_rows: usize,
}

#[pymethods]
impl PyLimits {
    #[new]
    #[pyo3(signature = (
        *,
        max_sql_bytes=None,
        max_depth=None,
        max_nodes=None,
        max_joins=None,
        max_subqueries=None,
        max_set_operations=None,
        max_in_list=None,
        max_projection=None,
        max_values_rows=None,
    ))]
    #[expect(clippy::too_many_arguments, reason = "one keyword argument per limit")]
    fn new(
        max_sql_bytes: Option<usize>,
        max_depth: Option<usize>,
        max_nodes: Option<usize>,
        max_joins: Option<usize>,
        max_subqueries: Option<usize>,
        max_set_operations: Option<usize>,
        max_in_list: Option<usize>,
        max_projection: Option<usize>,
        max_values_rows: Option<usize>,
    ) -> Self {
        let defaults = p14g::Limits::default();
        Self {
            max_sql_bytes: max_sql_bytes.unwrap_or(defaults.max_sql_bytes),
            max_depth: max_depth.unwrap_or(defaults.max_depth),
            max_nodes: max_nodes.unwrap_or(defaults.max_nodes),
            max_joins: max_joins.unwrap_or(defaults.max_joins),
            max_subqueries: max_subqueries.unwrap_or(defaults.max_subqueries),
            max_set_operations: max_set_operations.unwrap_or(defaults.max_set_operations),
            max_in_list: max_in_list.unwrap_or(defaults.max_in_list),
            max_projection: max_projection.unwrap_or(defaults.max_projection),
            max_values_rows: max_values_rows.unwrap_or(defaults.max_values_rows),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Limits(max_sql_bytes={}, max_depth={}, max_nodes={}, max_joins={}, max_subqueries={}, \
             max_set_operations={}, max_in_list={}, max_projection={}, max_values_rows={})",
            self.max_sql_bytes,
            self.max_depth,
            self.max_nodes,
            self.max_joins,
            self.max_subqueries,
            self.max_set_operations,
            self.max_in_list,
            self.max_projection,
            self.max_values_rows
        )
    }
}

impl PyLimits {
    fn to_limits(&self) -> p14g::Limits {
        p14g::Limits {
            max_sql_bytes: self.max_sql_bytes,
            max_depth: self.max_depth,
            max_nodes: self.max_nodes,
            max_joins: self.max_joins,
            max_subqueries: self.max_subqueries,
            max_set_operations: self.max_set_operations,
            max_in_list: self.max_in_list,
            max_projection: self.max_projection,
            max_values_rows: self.max_values_rows,
        }
    }
}

// ------------------------------------------------------------------ values

/// `None`, `bool`, `int`, `float` and `str` as an expression; `None` for anything else.
fn scalar_to_expr(value: &Bound<'_, PyAny>) -> PyResult<Option<ast::Expr>> {
    Ok(if value.is_none() {
        Some(ast::Literal::Null.into())
    } else if let Ok(b) = value.cast::<PyBool>() {
        Some(b.is_true().into())
    } else if value.is_instance_of::<PyInt>() {
        // through text, so that ints of any size keep every digit
        let digits = value.str()?.to_string();
        let number = |d: &str| ast::Expr::Literal(ast::Literal::Number(d.to_owned()));
        Some(match digits.strip_prefix('-') {
            Some(magnitude) => ast::Expr::Unary {
                op: ast::UnaryOperator::Minus,
                expr: Box::new(number(magnitude)),
            },
            None => number(&digits),
        })
    } else if let Ok(f) = value.cast::<PyFloat>() {
        Some(f.value().into())
    } else if let Ok(s) = value.cast::<PyString>() {
        Some(s.to_str()?.into())
    } else {
        None
    })
}

/// A value given to a filter or an `extra`, as an expression.
fn py_to_expr(value: &Bound<'_, PyAny>) -> PyResult<ast::Expr> {
    match scalar_to_expr(value)? {
        Some(expr) => Ok(expr),
        None => Err(PyTypeError::new_err(format!(
            "expected None, bool, int, float or str, not {}",
            value.get_type().name()?
        ))),
    }
}

// ------------------------------------------------------------------ policy

/// SQL that is safe to run, and what it is.
#[pyclass(frozen, module = "p14g", name = "SafeSql", get_all)]
struct PySafeSql {
    /// The SQL to send to the database.
    sql: String,
    /// Values for the placeholders p14g added, in order. Empty unless the policy uses `literals='params'`.
    ///
    /// The first is numbered one above the highest placeholder in the input, so append these to the
    /// parameters the input already needed.
    params: Vec<String>,
    /// 'select', 'insert', 'update' or 'delete'.
    kind: &'static str,
    /// The tables and views the statement uses, as it named them, sorted.
    tables: Vec<String>,
}

#[pymethods]
impl PySafeSql {
    fn __repr__(&self) -> String {
        format!(
            "SafeSql(sql={:?}, params={:?}, kind={:?}, tables={:?})",
            self.sql, self.params, self.kind, self.tables
        )
    }
}

/// A set of rules that untrusted SQL is checked against. Build it once and reuse it.
///
/// The positional arguments are `Select`, `Insert`, `Update` and `Delete` rules. A statement that no rule
/// allows is rejected.
#[pyclass(frozen, module = "p14g", name = "Policy")]
struct PyPolicy(Policy);

#[pymethods]
impl PyPolicy {
    /// `Policy[C]` in an annotation. The context type is for type checkers; nothing checks it at run time.
    #[classmethod]
    fn __class_getitem__<'py>(cls: &Bound<'py, PyType>, item: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        generic_alias(cls, item)
    }

    #[new]
    #[pyo3(signature = (
        *rules,
        functions=None,
        deny_functions=None,
        default_functions=true,
        operators=None,
        star_behaviour="expand",
        literals="inline",
        quote_identifiers="minimal",
        layout="multiline",
        qualify_builtins=false,
        max_rows=None,
        default_schema=None,
        dialect="postgres",
        limits=None,
    ))]
    #[expect(clippy::too_many_arguments, reason = "one keyword argument per option")]
    fn new(
        py: Python<'_>,
        rules: &Bound<'_, PyTuple>,
        functions: Option<Vec<String>>,
        deny_functions: Option<Vec<String>>,
        default_functions: bool,
        operators: Option<Vec<String>>,
        star_behaviour: &str,
        literals: &str,
        quote_identifiers: &str,
        layout: &str,
        qualify_builtins: bool,
        max_rows: Option<u64>,
        default_schema: Option<String>,
        dialect: &str,
        limits: Option<&Bound<'_, PyLimits>>,
    ) -> PyResult<Self> {
        let config = |e| to_py_err(py, e);
        let mut builder: PolicyBuilder<Context> = Policy::builder()
            .functions(functions.unwrap_or_default())
            .deny_functions(deny_functions.unwrap_or_default())
            .default_functions(default_functions)
            .star_behaviour(Star::parse(star_behaviour).map_err(config)?)
            .literals(Literals::parse(literals).map_err(config)?)
            .quote_identifiers(p14g::QuoteIdentifiers::parse(quote_identifiers).map_err(config)?)
            .layout(p14g::Layout::parse(layout).map_err(config)?)
            .qualify_builtins(qualify_builtins)
            .max_rows(max_rows)
            .dialect(p14g::Dialect::parse(dialect).map_err(config)?);
        if let Some(default_schema) = default_schema {
            builder = builder.default_schema(default_schema);
        }
        if let Some(operators) = operators {
            builder = builder.operators(parse_operators(py, &operators)?);
        }
        if let Some(limits) = limits {
            builder = builder.limits(limits.get().to_limits());
        }
        for rule in rules {
            builder = add_rule(py, builder, &rule)?;
        }
        builder.build().map(Self).map_err(config)
    }

    /// The `GRANT` statements that give `role` the table access this policy allows.
    ///
    /// `context` is passed to `extra` callables to learn which columns they set.
    #[pyo3(signature = (role, *, context=None))]
    fn grants(&self, py: Python<'_>, role: &str, context: Option<Py<PyAny>>) -> PyResult<Vec<String>> {
        let context = context.unwrap_or_else(|| py.None());
        self.0.grants(role, &context).map_err(|e| to_py_err(py, e))
    }

    /// Check one SQL statement against the policy and return it rewritten so it is safe to run.
    ///
    /// Raises `P14gError` if the statement is not allowed.
    ///
    /// `context` is passed on to `filter` and `extra` callables. `allow` restricts the kinds of statement
    /// accepted by this call, for example `['select']`.
    #[pyo3(signature = (sql, *, context=None, allow=None))]
    fn rewrite(
        &self,
        py: Python<'_>,
        sql: &str,
        context: Option<Py<PyAny>>,
        allow: Option<Vec<String>>,
    ) -> PyResult<PySafeSql> {
        let allow = allow
            .map(|kinds| {
                kinds
                    .iter()
                    .map(|kind| StatementKind::parse(kind).map_err(|e| to_py_err(py, e)))
                    .collect::<PyResult<Vec<_>>>()
            })
            .transpose()?;
        let context = context.unwrap_or_else(|| py.None());
        let safe = self
            .0
            .rewrite_kinds(sql, &context, allow.as_deref())
            .map_err(|e| to_py_err(py, e))?;
        Ok(PySafeSql {
            sql: safe.sql,
            params: safe.params,
            kind: safe.kind.as_str(),
            tables: safe.tables,
        })
    }
}

fn add_rule(
    py: Python<'_>,
    builder: PolicyBuilder<Context>,
    rule: &Bound<'_, PyAny>,
) -> PyResult<PolicyBuilder<Context>> {
    if let Ok(select) = rule.cast::<PySelect>() {
        let select = select.get();
        let mut rule = p14g::Select::table(&select.table).only(select.only);
        if let Some(columns) = &select.columns {
            rule = rule.columns(columns);
        }
        if let Some(filter) = &select.filter {
            let filter = filter.clone_ref(py);
            rule = rule.try_filter(move |context: &Context| python_filter(&filter, context));
        }
        Ok(builder.select(rule))
    } else if let Ok(insert) = rule.cast::<PyInsert>() {
        let insert = insert.get();
        let mut rule = p14g::Insert::table(&insert.table);
        if let Some(columns) = &insert.columns {
            rule = rule.columns(columns);
        }
        rule = match &insert.extra {
            Extra::None => rule,
            Extra::Fixed(values) => {
                let values = values.clone();
                rule.try_extra(move |_| Ok(values.clone()))
            }
            Extra::Callable(callable) => {
                let callable = callable.clone_ref(py);
                rule.try_extra(move |context: &Context| {
                    Python::attach(|py| extra_values(&callable.bind(py).call1((context.bind(py),))?))
                        .map_err(callback_error)
                })
            }
        };
        Ok(builder.insert(rule))
    } else if let Ok(update) = rule.cast::<PyUpdate>() {
        let update = update.get();
        let mut rule = p14g::Update::table(&update.table)
            .allow_unfiltered(update.allow_unfiltered)
            .only(update.only);
        if let Some(columns) = &update.columns {
            rule = rule.columns(columns);
        }
        if let Some(filter) = &update.filter {
            let filter = filter.clone_ref(py);
            rule = rule.try_filter(move |context: &Context| python_filter(&filter, context));
        }
        Ok(builder.update(rule))
    } else if let Ok(delete) = rule.cast::<PyDelete>() {
        let delete = delete.get();
        let mut rule = p14g::Delete::table(&delete.table)
            .allow_unfiltered(delete.allow_unfiltered)
            .only(delete.only);
        if let Some(filter) = &delete.filter {
            let filter = filter.clone_ref(py);
            rule = rule.try_filter(move |context: &Context| python_filter(&filter, context));
        }
        Ok(builder.delete(rule))
    } else {
        Err(PyTypeError::new_err(format!(
            "a rule must be a Select, Insert, Update or Delete, not {}",
            rule.get_type().name()?
        )))
    }
}

#[pymodule(gil_used = false)]
#[pyo3(name = "p14g")]
mod p14g_python {
    use pyo3::{
        prelude::*,
        types::{PyBool, PyFloat, PyFrozenSet, PyInt, PyString, PyTuple},
    };

    use super::{ErrorKind, functions};
    #[pymodule_export]
    use super::{P14gError, PyDelete, PyInsert, PyLimits, PyPolicy, PySafeSql, PySelect, PyUpdate};

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", env!("CARGO_PKG_VERSION"))?;
        let mut defaults: Vec<&str> = functions::defaults().collect();
        defaults.sort_unstable();
        m.add("DEFAULT_FUNCTIONS", PyFrozenSet::new(m.py(), defaults)?)?;
        // so that code matching on `error.kind` has something to import
        let kinds = [
            ErrorKind::Parse,
            ErrorKind::Unsupported,
            ErrorKind::Denied,
            ErrorKind::Limit,
            ErrorKind::Config,
            ErrorKind::Callback,
        ]
        .map(ErrorKind::as_str);
        m.add("ERROR_KINDS", PyTuple::new(m.py(), kinds)?)?;
        // the type of a value given to a filter or an `extra`, for annotations
        let py = m.py();
        let members = (
            py.None(),
            py.get_type::<PyBool>(),
            py.get_type::<PyInt>(),
            py.get_type::<PyFloat>(),
            py.get_type::<PyString>(),
        );
        m.add("Value", py.import("typing")?.getattr("Union")?.get_item(members)?)?;
        Ok(())
    }
}
