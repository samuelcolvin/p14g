//! Python bindings for pgsafe.
#![expect(clippy::absolute_paths, reason = "in the code `#[pyclass(hash)]` expands to")]

use pgsafe::{ErrorKind, Literals, Mapper, Op, PolicyBuilder, Star, StatementKind, ast, functions};
use pyo3::{
    create_exception,
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    types::{PyBool, PyDict, PyFloat, PyInt, PyString, PyTuple, PyType},
};

/// The context handed to `check()`, passed on untouched to `extra` callables and mappers.
type Context = Py<PyAny>;
type Policy = pgsafe::Policy<Context>;

create_exception!(
    pgsafe,
    PgSafeError,
    PyValueError,
    "A statement was rejected, or a policy could not be built.

`kind` is one of 'parse', 'unsupported', 'denied', 'limit', 'config' or 'callback'. `message` is the text
without the position, and `line` and `column` give the position in the SQL when it is known."
);

/// Convert a pgsafe error, keeping the exception a callback raised as its cause.
fn to_py_err(py: Python<'_>, mut error: pgsafe::Error) -> PyErr {
    let cause = error.take_source().and_then(|source| source.downcast::<PyErr>().ok());
    let err = PgSafeError::new_err(error.to_string());
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

/// An error raised inside a callback, to be carried through pgsafe and raised again as the cause.
fn callback_error(error: PyErr) -> pgsafe::Error {
    pgsafe::Error::callback_source(error)
}

fn ident(py: Python<'_>, value: &str) -> PyResult<ast::Ident> {
    ast::Ident::new(value).map_err(|e| to_py_err(py, e))
}

fn optional_ident(py: Python<'_>, value: Option<&str>) -> PyResult<Option<ast::Ident>> {
    value.map(|v| ident(py, v)).transpose()
}

fn repr_list(items: Option<&Vec<String>>) -> String {
    items.map_or_else(|| "None".to_owned(), |items| format!("{items:?}"))
}

// ------------------------------------------------------------------ rules

/// Allows reading from a table or view.
///
/// Every mention of a column counts as a read, wherever it is: in the select list, in a `WHERE` or
/// `ORDER BY`, or in the `WHERE` of an `UPDATE`.
#[pyclass(frozen, module = "pgsafe", name = "Select")]
struct PySelect {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    #[pyo3(get)]
    operators: Option<Vec<String>>,
    #[pyo3(get)]
    only: bool,
}

#[pymethods]
impl PySelect {
    #[new]
    #[pyo3(signature = (table, *, columns=None, operators=None, only=false))]
    fn new(
        py: Python<'_>,
        table: String,
        columns: Option<Vec<String>>,
        operators: Option<Vec<String>>,
        only: bool,
    ) -> PyResult<Self> {
        if let Some(operators) = &operators {
            parse_operators(py, operators)?;
        }
        Ok(Self {
            table,
            columns,
            operators,
            only,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Select({:?}, columns={}, operators={}, only={})",
            self.table,
            repr_list(self.columns.as_ref()),
            repr_list(self.operators.as_ref()),
            repr_bool(self.only)
        )
    }
}

fn repr_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
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
/// `extra` gives columns pgsafe sets on every inserted row: a dict, or a callable that takes the context
/// passed to `check()` and returns a dict. A statement that sets one of those columns itself is rejected.
#[pyclass(frozen, module = "pgsafe", name = "Insert")]
struct PyInsert {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    extra: Extra,
}

#[pymethods]
impl PyInsert {
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
#[pyclass(frozen, module = "pgsafe", name = "Update")]
struct PyUpdate {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    columns: Option<Vec<String>>,
    #[pyo3(get)]
    allow_unfiltered: bool,
    #[pyo3(get)]
    only: bool,
}

#[pymethods]
impl PyUpdate {
    #[new]
    #[pyo3(signature = (table, *, columns=None, allow_unfiltered=false, only=false))]
    fn new(table: String, columns: Option<Vec<String>>, allow_unfiltered: bool, only: bool) -> Self {
        Self {
            table,
            columns,
            allow_unfiltered,
            only,
        }
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
#[pyclass(frozen, module = "pgsafe", name = "Delete")]
struct PyDelete {
    #[pyo3(get)]
    table: String,
    #[pyo3(get)]
    allow_unfiltered: bool,
    #[pyo3(get)]
    only: bool,
}

#[pymethods]
impl PyDelete {
    #[new]
    #[pyo3(signature = (table, *, allow_unfiltered=false, only=false))]
    fn new(table: String, allow_unfiltered: bool, only: bool) -> Self {
        Self {
            table,
            allow_unfiltered,
            only,
        }
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
#[pyclass(frozen, module = "pgsafe", name = "Limits", get_all)]
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
        let defaults = pgsafe::Limits::default();
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
    fn to_limits(&self) -> pgsafe::Limits {
        pgsafe::Limits {
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

// ------------------------------------------------------------------ nodes seen by mappers

/// A table or view in `FROM`, or the target of a write.
#[pyclass(frozen, eq, hash, module = "pgsafe", name = "Table")]
#[derive(PartialEq, Eq, Hash)]
struct PyTable(ast::Table);

#[pymethods]
impl PyTable {
    #[new]
    #[pyo3(signature = (name, *, schema=None, alias=None, only=false))]
    fn new(py: Python<'_>, name: &str, schema: Option<&str>, alias: Option<&str>, only: bool) -> PyResult<Self> {
        Ok(Self(ast::Table {
            schema: optional_ident(py, schema)?,
            name: ident(py, name)?,
            alias: optional_ident(py, alias)?,
            only,
        }))
    }

    /// Whether the table is written `ONLY name`, which leaves out rows of its inheritance children.
    #[getter]
    fn only(&self) -> bool {
        self.0.only
    }

    #[getter]
    fn name(&self) -> &str {
        self.0.name.as_str()
    }

    #[getter]
    fn schema(&self) -> Option<&str> {
        self.0.schema.as_ref().map(ast::Ident::as_str)
    }

    #[getter]
    fn alias(&self) -> Option<&str> {
        self.0.alias.as_ref().map(ast::Ident::as_str)
    }

    fn __repr__(&self) -> String {
        format!(
            "Table({:?}, schema={}, alias={}, only={})",
            self.name(),
            repr_option(self.schema()),
            repr_option(self.alias()),
            repr_bool(self.0.only)
        )
    }
}

fn repr_option(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_owned(), |v| format!("{v:?}"))
}

/// A reference to a column. `table` is the name or alias of the table it belongs to.
#[pyclass(frozen, eq, hash, module = "pgsafe", name = "Column")]
#[derive(PartialEq, Eq, Hash)]
struct PyColumn(ast::Column);

#[pymethods]
impl PyColumn {
    #[new]
    #[pyo3(signature = (name, *, table=None))]
    fn new(py: Python<'_>, name: &str, table: Option<&str>) -> PyResult<Self> {
        Ok(Self(ast::Column {
            table: optional_ident(py, table)?,
            name: ident(py, name)?,
        }))
    }

    #[getter]
    fn name(&self) -> &str {
        self.0.name.as_str()
    }

    #[getter]
    fn table(&self) -> Option<&str> {
        self.0.table.as_ref().map(ast::Ident::as_str)
    }

    fn __repr__(&self) -> String {
        format!("Column({:?}, table={})", self.name(), repr_option(self.table()))
    }
}

/// A function call. `args` holds `Column`, `Function`, `Literal` and opaque `Expr` objects.
#[pyclass(frozen, eq, hash, module = "pgsafe", name = "Function")]
#[derive(PartialEq, Eq, Hash)]
struct PyFunction(ast::Function);

#[pymethods]
impl PyFunction {
    #[new]
    #[pyo3(signature = (name, args=None, *, schema=None))]
    fn new(py: Python<'_>, name: &str, args: Option<Vec<Bound<'_, PyAny>>>, schema: Option<&str>) -> PyResult<Self> {
        let args = args
            .unwrap_or_default()
            .iter()
            .map(py_to_expr)
            .collect::<PyResult<_>>()?;
        let mut function = ast::Function::call(ident(py, name)?, args);
        function.schema = optional_ident(py, schema)?;
        Ok(Self(function))
    }

    #[getter]
    fn name(&self) -> &str {
        self.0.name.as_str()
    }

    #[getter]
    fn schema(&self) -> Option<&str> {
        self.0.schema.as_ref().map(ast::Ident::as_str)
    }

    /// The arguments. Empty for `f(*)` and for keywords such as `CURRENT_DATE`.
    #[getter]
    fn args(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
        match &self.0.args {
            ast::FunctionArgs::List(args) => args.iter().map(|arg| expr_to_py(py, arg.clone())).collect(),
            _ => Ok(Vec::new()),
        }
    }

    /// A copy with a different name, schema or arguments, keeping `DISTINCT`, `FILTER`, `OVER` and so on.
    ///
    /// `schema=None` removes the schema; leave `schema` out to keep it.
    #[pyo3(signature = (**kwargs))]
    fn replace(&self, py: Python<'_>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut function = self.0.clone();
        for (key, value) in kwargs.into_iter().flatten() {
            let key: String = key.extract()?;
            match key.as_str() {
                "name" => function.name = ident(py, &value.extract::<String>()?)?,
                "schema" => function.schema = optional_ident(py, value.extract::<Option<String>>()?.as_deref())?,
                "args" => {
                    let args: Vec<Bound<'_, PyAny>> = value.extract()?;
                    function.args = ast::FunctionArgs::List(args.iter().map(py_to_expr).collect::<PyResult<_>>()?);
                }
                other => {
                    return Err(PyTypeError::new_err(format!(
                        "replace() got an unexpected keyword argument '{other}'"
                    )));
                }
            }
        }
        Ok(Self(function))
    }

    fn __repr__(&self) -> String {
        format!("Function({:?}, schema={})", self.name(), repr_option(self.schema()))
    }
}

/// A literal value: `None`, a `bool`, a number or a `str`.
#[pyclass(frozen, eq, hash, module = "pgsafe", name = "Literal")]
#[derive(PartialEq, Eq, Hash)]
struct PyLiteral(ast::Literal);

#[pymethods]
impl PyLiteral {
    #[new]
    fn new(value: &Bound<'_, PyAny>) -> PyResult<Self> {
        match scalar_to_expr(value)? {
            Some(ast::Expr::Literal(literal)) => Ok(Self(literal)),
            Some(_) => Err(PyValueError::new_err(
                "a negative or non-finite number is not a single literal, return the number itself instead",
            )),
            None => Err(PyTypeError::new_err(
                "a literal must be None, a bool, an int, a float or a str",
            )),
        }
    }

    /// The value. A number that fits neither `int` nor `float` exactly is returned as the `str` of its digits.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(match &self.0 {
            ast::Literal::Boolean(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
            ast::Literal::Number(number) => {
                if let Ok(int) = number.parse::<u64>() {
                    int.into_pyobject(py)?.into_any().unbind()
                } else if let Ok(float) = number.parse::<f64>()
                    && number.len() <= 15
                {
                    float.into_pyobject(py)?.into_any().unbind()
                } else {
                    number.into_pyobject(py)?.into_any().unbind()
                }
            }
            ast::Literal::String(s) => s.into_pyobject(py)?.into_any().unbind(),
            _ => py.None(),
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Literal({})", self.value(py)?.bind(py).repr()?))
    }
}

/// Any other expression. It can be passed along, for example as a function argument, but not inspected.
#[pyclass(frozen, eq, hash, module = "pgsafe", name = "Expr")]
#[derive(PartialEq, Eq, Hash)]
struct PyExpr(ast::Expr);

#[pymethods]
impl PyExpr {
    #[expect(clippy::unused_self, reason = "a method as far as Python is concerned")]
    fn __repr__(&self) -> &'static str {
        "Expr(...)"
    }
}

fn expr_to_py(py: Python<'_>, expr: ast::Expr) -> PyResult<Py<PyAny>> {
    Ok(match expr {
        ast::Expr::Column(column) => Py::new(py, PyColumn(column))?.into_any(),
        ast::Expr::Function(function) => Py::new(py, PyFunction(function))?.into_any(),
        ast::Expr::Literal(literal) => Py::new(py, PyLiteral(literal))?.into_any(),
        other => Py::new(py, PyExpr(other))?.into_any(),
    })
}

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

/// Anything a mapper or an `extra` may hand back as an expression.
fn py_to_expr(value: &Bound<'_, PyAny>) -> PyResult<ast::Expr> {
    if let Some(expr) = scalar_to_expr(value)? {
        Ok(expr)
    } else if let Ok(column) = value.cast::<PyColumn>() {
        Ok(ast::Expr::Column(column.get().0.clone()))
    } else if let Ok(function) = value.cast::<PyFunction>() {
        Ok(ast::Expr::Function(function.get().0.clone()))
    } else if let Ok(literal) = value.cast::<PyLiteral>() {
        Ok(ast::Expr::Literal(literal.get().0.clone()))
    } else if let Ok(expr) = value.cast::<PyExpr>() {
        Ok(expr.get().0.clone())
    } else {
        Err(PyTypeError::new_err(format!(
            "expected a Column, Function, Literal, Expr, None, bool, int, float or str, not {}",
            value.get_type().name()?
        )))
    }
}

// ------------------------------------------------------------------ mappers

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    Table,
    Column,
    Function,
    Literal,
}

impl NodeKind {
    fn name(self) -> &'static str {
        match self {
            Self::Table => "Table",
            Self::Column => "Column",
            Self::Function => "Function",
            Self::Literal => "Literal",
        }
    }
}

/// A function registered with `@mapper(...)`, to be passed to `Policy(mappers=[...])`.
///
/// It can still be called like the function it wraps.
#[pyclass(frozen, module = "pgsafe", name = "Mapper")]
struct PyMapper {
    kind: NodeKind,
    function: Py<PyAny>,
}

#[pymethods]
impl PyMapper {
    #[pyo3(signature = (*args, **kwargs))]
    fn __call__(
        &self,
        py: Python<'_>,
        args: &Bound<'_, PyTuple>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        self.function.call(py, args, kwargs)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "<Mapper of {} {}>",
            self.kind.name(),
            self.function.bind(py).repr()?
        ))
    }
}

/// What `mapper(kind)` returns: the decorator that wraps a function for that kind of node.
#[pyclass(frozen, module = "pgsafe", name = "_MapperDecorator")]
struct PyMapperDecorator {
    kind: NodeKind,
}

#[pymethods]
impl PyMapperDecorator {
    fn __call__(&self, function: Py<PyAny>) -> PyMapper {
        PyMapper {
            kind: self.kind,
            function,
        }
    }
}

/// Register a function as a mapper for one kind of node: `@mapper(Table)`, `@mapper(Column)`,
/// `@mapper(Function)` or `@mapper(Literal)`.
///
/// The function is called with the node and the context passed to `check()`, and returns the node to use
/// in its place. A table mapper returns a `Table`; the others may return any expression, or a plain value.
/// Mappers run after the statement has passed the policy, and what they return is not checked against it.
#[pyfunction]
fn mapper(kind: &Bound<'_, PyType>) -> PyResult<PyMapperDecorator> {
    let py = kind.py();
    let kind = if kind.is(py.get_type::<PyTable>()) {
        NodeKind::Table
    } else if kind.is(py.get_type::<PyColumn>()) {
        NodeKind::Column
    } else if kind.is(py.get_type::<PyFunction>()) {
        NodeKind::Function
    } else if kind.is(py.get_type::<PyLiteral>()) {
        NodeKind::Literal
    } else {
        return Err(PyTypeError::new_err(
            "mapper() takes Table, Column, Function or Literal",
        ));
    };
    Ok(PyMapperDecorator { kind })
}

struct PythonMapper {
    kind: NodeKind,
    function: Py<PyAny>,
}

impl PythonMapper {
    fn call<'py>(&self, py: Python<'py>, node: Py<PyAny>, context: &Context) -> PyResult<Bound<'py, PyAny>> {
        self.function.bind(py).call1((node, context.bind(py)))
    }

    fn map_expr(&self, node: ast::Expr, context: &Context) -> pgsafe::Result<ast::Expr> {
        Python::attach(|py| {
            let node = expr_to_py(py, node)?;
            py_to_expr(&self.call(py, node, context)?)
        })
        .map_err(callback_error)
    }
}

impl Mapper<Context> for PythonMapper {
    fn map_table(&self, table: ast::Table, context: &Context) -> pgsafe::Result<ast::Table> {
        if self.kind != NodeKind::Table {
            return Ok(table);
        }
        Python::attach(|py| {
            let node = Py::new(py, PyTable(table))?.into_any();
            let result = self.call(py, node, context)?;
            let table = result
                .cast::<PyTable>()
                .map_err(|_| PyTypeError::new_err("a Table mapper must return a Table"))?;
            Ok(table.get().0.clone())
        })
        .map_err(callback_error)
    }

    fn map_column(&self, column: ast::Column, context: &Context) -> pgsafe::Result<ast::Expr> {
        if self.kind == NodeKind::Column {
            self.map_expr(ast::Expr::Column(column), context)
        } else {
            Ok(ast::Expr::Column(column))
        }
    }

    fn map_function(&self, function: ast::Function, context: &Context) -> pgsafe::Result<ast::Expr> {
        if self.kind == NodeKind::Function {
            self.map_expr(ast::Expr::Function(function), context)
        } else {
            Ok(ast::Expr::Function(function))
        }
    }

    fn map_literal(&self, literal: ast::Literal, context: &Context) -> pgsafe::Result<ast::Expr> {
        if self.kind == NodeKind::Literal {
            self.map_expr(ast::Expr::Literal(literal), context)
        } else {
            Ok(ast::Expr::Literal(literal))
        }
    }
}

// ------------------------------------------------------------------ policy

/// SQL that is safe to run, and what it is.
#[pyclass(frozen, module = "pgsafe", name = "SafeSql", get_all)]
struct PySafeSql {
    /// The SQL to send to the database.
    sql: String,
    /// Values for the placeholders pgsafe added, in order. Empty unless the policy uses `literals='params'`.
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
#[pyclass(frozen, module = "pgsafe", name = "Policy")]
struct PyPolicy(Policy);

#[pymethods]
impl PyPolicy {
    #[new]
    #[pyo3(signature = (
        *rules,
        functions=None,
        deny_functions=None,
        default_functions=true,
        operators=None,
        star_behaviour="expand",
        literals="inline",
        max_rows=None,
        default_schema=None,
        dialect="postgres",
        limits=None,
        mappers=None,
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
        max_rows: Option<u64>,
        default_schema: Option<String>,
        dialect: &str,
        limits: Option<&Bound<'_, PyLimits>>,
        mappers: Option<Vec<Bound<'_, PyMapper>>>,
    ) -> PyResult<Self> {
        let config = |e| to_py_err(py, e);
        let mut builder: PolicyBuilder<Context> = Policy::builder()
            .functions(functions.unwrap_or_default())
            .deny_functions(deny_functions.unwrap_or_default())
            .default_functions(default_functions)
            .star_behaviour(Star::parse(star_behaviour).map_err(config)?)
            .literals(Literals::parse(literals).map_err(config)?)
            .max_rows(max_rows)
            .dialect(pgsafe::Dialect::parse(dialect).map_err(config)?);
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
        for mapper in mappers.into_iter().flatten() {
            let mapper = mapper.get();
            builder = builder.mapper(PythonMapper {
                kind: mapper.kind,
                function: mapper.function.clone_ref(py),
            });
        }
        builder.build().map(Self).map_err(config)
    }

    /// Check one SQL statement and return SQL that is safe to run, or raise `PgSafeError`.
    ///
    /// `context` is passed on to `extra` callables and mappers. `allow` restricts the kinds of statement
    /// accepted by this call, for example `['select']`.
    #[pyo3(signature = (sql, *, context=None, allow=None))]
    fn check(
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
            .check_kinds(sql, &context, allow.as_deref())
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
        let mut rule = pgsafe::Select::table(&select.table).only(select.only);
        if let Some(columns) = &select.columns {
            rule = rule.columns(columns);
        }
        if let Some(operators) = &select.operators {
            rule = rule.operators(parse_operators(py, operators)?);
        }
        Ok(builder.select(rule))
    } else if let Ok(insert) = rule.cast::<PyInsert>() {
        let insert = insert.get();
        let mut rule = pgsafe::Insert::table(&insert.table);
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
        let mut rule = pgsafe::Update::table(&update.table)
            .allow_unfiltered(update.allow_unfiltered)
            .only(update.only);
        if let Some(columns) = &update.columns {
            rule = rule.columns(columns);
        }
        Ok(builder.update(rule))
    } else if let Ok(delete) = rule.cast::<PyDelete>() {
        let delete = delete.get();
        Ok(builder.delete(
            pgsafe::Delete::table(&delete.table)
                .allow_unfiltered(delete.allow_unfiltered)
                .only(delete.only),
        ))
    } else {
        Err(PyTypeError::new_err(format!(
            "a rule must be a Select, Insert, Update or Delete, not {}",
            rule.get_type().name()?
        )))
    }
}

#[pymodule(gil_used = false)]
#[pyo3(name = "pgsafe")]
mod pgsafe_python {
    use pyo3::{
        prelude::*,
        types::{PyBool, PyFloat, PyFrozenSet, PyInt, PyString, PyTuple},
    };

    use super::{ErrorKind, functions};
    #[pymodule_export]
    use super::{
        PgSafeError, PyColumn, PyDelete, PyExpr, PyFunction, PyInsert, PyLimits, PyLiteral, PyMapper, PyPolicy,
        PySafeSql, PySelect, PyTable, PyUpdate, mapper,
    };

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
        // the type of what a mapper may return, for annotations
        let py = m.py();
        let members = (
            py.get_type::<PyColumn>(),
            py.get_type::<PyFunction>(),
            py.get_type::<PyLiteral>(),
            py.get_type::<PyExpr>(),
            py.None(),
            py.get_type::<PyBool>(),
            py.get_type::<PyInt>(),
            py.get_type::<PyFloat>(),
            py.get_type::<PyString>(),
        );
        m.add("ExprLike", py.import("typing")?.getattr("Union")?.get_item(members)?)?;
        Ok(())
    }
}
