from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal as _Literal, TypeAlias, final, overload

__all__ = [
    'DEFAULT_FUNCTIONS',
    'ERROR_KINDS',
    'Column',
    'Delete',
    'Expr',
    'ExprLike',
    'Function',
    'Insert',
    'Limits',
    'Literal',
    'Mapper',
    'PgSafeError',
    'Policy',
    'SafeSql',
    'Select',
    'Table',
    'Update',
    '__version__',
    'mapper',
]

__version__: str

DEFAULT_FUNCTIONS: frozenset[str]
"""The functions a policy allows unless `default_functions=False`."""

ERROR_KINDS: tuple[str, ...]
"""Every value `PgSafeError.kind` can take."""

_Scalar: TypeAlias = None | bool | int | float | str
ExprLike: TypeAlias = Column | Function | Literal | Expr | None | bool | int | float | str
"""What a mapper or an `extra` may give as a value."""

_Operator: TypeAlias = _Literal[
    '=', '!=', '<>', '<', '<=', '>', '>=', 'and', 'or', 'not', '+', '-', '*', '/', '%', '||',
    'like', 'ilike', 'similar to', '~', 'in', 'between', 'is', 'is distinct from', '->', '@>',
]  # fmt: skip
_Kind: TypeAlias = _Literal['select', 'insert', 'update', 'delete']

class PgSafeError(ValueError):
    """A statement was rejected, or a policy could not be built."""

    kind: _Literal['parse', 'unsupported', 'denied', 'limit', 'config', 'callback']
    message: str
    """The error without the position."""
    line: int | None
    column: int | None

@final
class Select:
    """Allows reading from a table or view.

    Every mention of a column counts as a read, wherever it is: in the select list, in a `WHERE` or
    `ORDER BY`, or in the `WHERE` of an `UPDATE`.

    Without `columns`, every column is allowed. Without `operators`, the policy's default operators apply.
    """

    def __new__(
        cls, table: str, *, columns: Sequence[str] | None = None, operators: Sequence[_Operator] | None = None
    ) -> Select: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str] | None: ...
    @property
    def operators(self) -> list[str] | None: ...

@final
class Insert:
    """Allows `INSERT INTO table (columns) VALUES ...`.

    `extra` gives columns pgsafe sets on every inserted row: a dict, or a callable that takes the context
    passed to `check()` and returns a dict. A statement that sets one of those columns itself is rejected.
    """

    def __new__(
        cls,
        table: str,
        *,
        columns: Sequence[str] | None = None,
        extra: Mapping[str, ExprLike] | Callable[[Any], Mapping[str, ExprLike]] | None = None,
    ) -> Insert: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str] | None: ...

@final
class Update:
    """Allows `UPDATE table SET column = ...` for the listed columns, or any column without `columns`.

    An `UPDATE` with no `WHERE` is rejected unless `allow_unfiltered` is set. That catches mistakes, it is
    not a security control: `WHERE true` passes.
    """

    def __new__(cls, table: str, *, columns: Sequence[str] | None = None, allow_unfiltered: bool = False) -> Update: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str] | None: ...
    @property
    def allow_unfiltered(self) -> bool: ...

@final
class Delete:
    """Allows `DELETE FROM table`. A `DELETE` with no `WHERE` is rejected unless `allow_unfiltered` is set."""

    def __new__(cls, table: str, *, allow_unfiltered: bool = False) -> Delete: ...
    @property
    def table(self) -> str: ...
    @property
    def allow_unfiltered(self) -> bool: ...

@final
class Limits:
    """Bounds on the size and shape of a statement, checked before any rule."""

    def __new__(
        cls,
        *,
        max_sql_bytes: int | None = None,
        max_depth: int | None = None,
        max_nodes: int | None = None,
        max_joins: int | None = None,
        max_subqueries: int | None = None,
        max_set_operations: int | None = None,
        max_in_list: int | None = None,
        max_projection: int | None = None,
        max_values_rows: int | None = None,
    ) -> Limits: ...
    @property
    def max_sql_bytes(self) -> int: ...
    @property
    def max_depth(self) -> int: ...
    @property
    def max_nodes(self) -> int: ...
    @property
    def max_joins(self) -> int: ...
    @property
    def max_subqueries(self) -> int: ...
    @property
    def max_set_operations(self) -> int: ...
    @property
    def max_in_list(self) -> int: ...
    @property
    def max_projection(self) -> int: ...
    @property
    def max_values_rows(self) -> int: ...

@final
class Table:
    """A table or view in `FROM`, or the target of a write."""

    def __new__(cls, name: str, *, schema: str | None = None, alias: str | None = None) -> Table: ...
    @property
    def name(self) -> str: ...
    @property
    def schema(self) -> str | None: ...
    @property
    def alias(self) -> str | None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Column:
    """A reference to a column. `table` is the name or alias of the table it belongs to."""

    def __new__(cls, name: str, *, table: str | None = None) -> Column: ...
    @property
    def name(self) -> str: ...
    @property
    def table(self) -> str | None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Function:
    """A function call."""

    def __new__(cls, name: str, args: Sequence[ExprLike] | None = None, *, schema: str | None = None) -> Function: ...
    @property
    def name(self) -> str: ...
    @property
    def schema(self) -> str | None: ...
    @property
    def args(self) -> list[Column | Function | Literal | Expr]:
        """The arguments. Empty for `f(*)` and for keywords such as `CURRENT_DATE`."""
    def replace(self, *, name: str = ..., schema: str | None = ..., args: Sequence[ExprLike] = ...) -> Function:
        """A copy with a different name, schema or arguments, keeping `DISTINCT`, `FILTER`, `OVER` and so on.

        `schema=None` removes the schema; leave `schema` out to keep it.
        """
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Literal:
    """A literal value: `None`, a `bool`, a number or a `str`."""

    def __new__(cls, value: _Scalar) -> Literal: ...
    @property
    def value(self) -> _Scalar:
        """The value. A number that fits neither `int` nor `float` exactly is the `str` of its digits."""
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Expr:
    """Any other expression. It can be passed along, for example as a function argument, but not inspected."""

    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Mapper:
    """A function registered with `@mapper(...)`, to be passed to `Policy(mappers=[...])`.

    It can still be called like the function it wraps.
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...

@overload
def mapper(kind: type[Table]) -> Callable[[Callable[[Table, Any], Table]], Mapper]:
    """Register a function as a mapper for one kind of node.

    The function is called with the node and the context passed to `check()`, and returns the node to use
    in its place. A table mapper returns a `Table`; the others may return any expression, or a plain value.

    Mappers run after the statement has passed the policy, and what they return is not checked against it.
    """

@overload
def mapper(kind: type[Column]) -> Callable[[Callable[[Column, Any], ExprLike]], Mapper]: ...
@overload
def mapper(kind: type[Function]) -> Callable[[Callable[[Function, Any], ExprLike]], Mapper]: ...
@overload
def mapper(kind: type[Literal]) -> Callable[[Callable[[Literal, Any], ExprLike]], Mapper]: ...

@final
class SafeSql:
    """SQL that is safe to run, and what it is."""

    @property
    def sql(self) -> str:
        """The SQL to send to the database."""
    @property
    def params(self) -> list[str]:
        """Values for the placeholders pgsafe added, in order. Empty unless the policy uses `literals='params'`.

        The first is numbered one above the highest placeholder in the input, so append these to the
        parameters the input already needed.
        """
    @property
    def kind(self) -> _Kind: ...
    @property
    def tables(self) -> list[str]:
        """The tables and views the statement uses, as it named them, sorted."""

@final
class Policy:
    """A set of rules that untrusted SQL is checked against. Build it once and reuse it.

    A statement that no rule allows is rejected.

    Args:
        rules: What may be read and written.
        functions: Functions to allow on top of the defaults, as `name` or `schema.name`.
        deny_functions: Functions to forbid that would otherwise be allowed.
        default_functions: Whether to start from `DEFAULT_FUNCTIONS`.
        operators: Operators for rules that do not list their own, and for expressions that touch no table.
            The default is everything except regular expressions (`~` and `similar to`).
        star_behaviour: What to do with `*`. `expand` replaces it with the columns the rule allows, `reject`
            refuses it, and `allow` leaves it alone but refuses it on a table whose rule lists columns.
        literals: `inline` writes string literals into the SQL, escaped. `params` replaces them with
            placeholders and returns the values in `SafeSql.params`.
        max_rows: Cap on the rows a `SELECT` returns: a missing `LIMIT` is added and a larger one reduced.
        dialect: The dialect of the input: `postgres`, `generic`, `ansi`, `mysql` or `sqlite`.
        limits: Bounds on the size of a statement.
        mappers: Functions decorated with `@mapper(...)`, run in order on statements that pass.
    """

    def __new__(
        cls,
        *rules: Select | Insert | Update | Delete,
        functions: Sequence[str] | None = None,
        deny_functions: Sequence[str] | None = None,
        default_functions: bool = True,
        operators: Sequence[_Operator] | None = None,
        star_behaviour: _Literal['expand', 'reject', 'allow'] = 'expand',
        literals: _Literal['inline', 'params'] = 'inline',
        max_rows: int | None = None,
        dialect: _Literal['postgres', 'generic', 'ansi', 'mysql', 'sqlite'] = 'postgres',
        limits: Limits | None = None,
        mappers: Sequence[Mapper] | None = None,
    ) -> Policy: ...
    def check(self, sql: str, *, context: Any = None, allow: Sequence[_Kind] | None = None) -> SafeSql:
        """Check one SQL statement and return SQL that is safe to run, or raise `PgSafeError`.

        `context` is passed on to `extra` callables and mappers. `allow` restricts the kinds of statement
        accepted by this call, for example `['select']`.
        """
