from collections.abc import Callable, Mapping, Sequence
from typing import Any, Generic, Literal as _Literal, LiteralString, TypeAlias, final, overload

from typing_extensions import TypeVar

__all__ = [
    'DEFAULT_FUNCTIONS',
    'ERROR_KINDS',
    'Delete',
    'Insert',
    'Limits',
    'P14gError',
    'Policy',
    'SafeSql',
    'Select',
    'Update',
    'Value',
    '__version__',
]

__version__: str

DEFAULT_FUNCTIONS: frozenset[str]
"""The functions a policy allows unless `default_functions=False`."""

ERROR_KINDS: tuple[str, ...]
"""Every value `P14gError.kind` can take."""

# contravariant, since it is only ever an argument; named for what it is rather than its variance
_C = TypeVar('_C', contravariant=True, default=Any)  # noqa: PLC0105
"""The type of the `context` passed to `rewrite()` and `grants()`, and on to filters and `extra` callables.

`Policy[C]` is inferred from the rules it is built from. Rules with no callback take any context. Where every callback accepts `None`, `context` may be left out.
"""

Value: TypeAlias = None | bool | int | float | str
"""A value given to a filter or an `extra`."""

_FilterSql: TypeAlias = LiteralString | tuple[LiteralString, Mapping[str, Value | list[Value]]]
"""A filter's SQL, alone or with values for its `:name` placeholders. A list is for `IN (:name)`."""
_Filter: TypeAlias = _FilterSql | Callable[[_C], _FilterSql]

_Operator: TypeAlias = _Literal[
    '=', '!=', '<>', '<', '<=', '>', '>=', 'and', 'or', 'not', '+', '-', '*', '/', '%', '||',
    'like', 'ilike', 'similar to', '~', 'in', 'between', 'is', 'is distinct from', '->', '@>',
]  # fmt: skip
_Kind: TypeAlias = _Literal['select', 'insert', 'update', 'delete']

class P14gError(ValueError):
    """A statement was rejected, or a policy could not be built."""

    kind: _Literal['parse', 'unsupported', 'denied', 'limit', 'config', 'callback']
    message: str
    """The error without the position."""
    line: int | None
    column: int | None

@final
class Select(Generic[_C]):
    """Allows reading the listed columns of a table or view.

    Every mention of a column counts as a read, wherever it is: in the select list, in a `WHERE` or
    `ORDER BY`, or in the `WHERE` of an `UPDATE`.

    For security reasons, all column names allowed need to be listed: there is no rule that allows every column,
    and `'*'` in the list is an error. Postgres reads `t.name` as the function call `name(t)` when `t` has no column `name`, so a name p14g cannot be
    sure is a column could call any function that takes the table's row. See "Why every column is listed" in the
    README.

    `filter` is a condition every row read through this rule has to meet. It is a function of the context passed
    to `rewrite()` that returns an SQL expression and the values for its `:name` placeholders:

        def org(context):
            return 'org = :org_id and status in (:statuses)', {'org_id': context.org_id, 'statuses': ['a', 'b']}

    p14g parses the expression and writes each value as an escaped literal; nothing is pasted into the output.
    A list is allowed where the placeholder is the only item of an `IN (...)`. The expression may use
    columns and functions the rule does not otherwise allow, but not a subquery. A filter with no values can be
    returned, or given, as a plain string. Be as careful with the functions a filter calls as with those added to
    `Policy(functions=...)`: p14g does not check them.

    In a `SELECT` the table is replaced by a subquery with the filter as its `WHERE`. Postgres may evaluate the
    statement's own conditions on a row before the filter's, so an error such as a division by zero can reveal
    something about rows the filter excludes; row-level security does not have that gap.

    Set `only` when the table has inheritance children the policy should not reach: Postgres includes their rows
    in a query on the parent, and checks privileges on the parent alone. With `only`, p14g writes the table as
    `ONLY table`. Do not set it for a partitioned table, whose parent holds no rows. Every `Select`, `Update`
    and `Delete` rule for one table must agree on it.
    """

    def __new__(
        cls,
        table: str,
        columns: Sequence[str],
        *,
        only: bool = False,
        filter: _Filter[_C] | None = None,
    ) -> Select[_C]: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str]: ...
    @property
    def only(self) -> bool: ...

@final
class Insert(Generic[_C]):
    """Allows `INSERT INTO table (columns) VALUES ...`.

    `extra` gives columns p14g sets on every inserted row: a dict, or a callable that takes the context
    passed to `rewrite()` and returns a dict. A statement that sets one of those columns itself is rejected.
    """

    def __new__(
        cls,
        table: str,
        *,
        columns: Sequence[str] | None = None,
        extra: Mapping[str, Value] | Callable[[_C], Mapping[str, Value]] | None = None,
    ) -> Insert[_C]: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str] | None: ...

@final
class Update(Generic[_C]):
    """Allows `UPDATE table SET column = ...` for the listed columns, or any column without `columns`.

    An `UPDATE` with no `WHERE` is rejected unless `allow_unfiltered` is set. That catches mistakes, it is
    not a security control: `WHERE true` passes.

    `only` writes the table as `ONLY table`, see `Select`.

    `filter` is a condition every row the statement updates has to meet, written like the `filter` of `Select`.
    It is added to the statement's `WHERE` with `AND`. A statement that sets a column the filter uses is rejected,
    so a row cannot be moved out of it.
    """

    def __new__(
        cls,
        table: str,
        *,
        columns: Sequence[str] | None = None,
        allow_unfiltered: bool = False,
        only: bool = False,
        filter: _Filter[_C] | None = None,
    ) -> Update[_C]: ...
    @property
    def table(self) -> str: ...
    @property
    def columns(self) -> list[str] | None: ...
    @property
    def allow_unfiltered(self) -> bool: ...
    @property
    def only(self) -> bool: ...

@final
class Delete(Generic[_C]):
    """Allows `DELETE FROM table`. A `DELETE` with no `WHERE` is rejected unless `allow_unfiltered` is set.

    `only` writes the table as `ONLY table`, see `Select`.

    `filter` is a condition every row the statement deletes has to meet, written like the `filter` of `Select`.
    It is added to the statement's `WHERE` with `AND`. There can be one `Delete` rule for a table.
    """

    def __new__(
        cls, table: str, *, allow_unfiltered: bool = False, only: bool = False, filter: _Filter[_C] | None = None
    ) -> Delete[_C]: ...
    @property
    def table(self) -> str: ...
    @property
    def allow_unfiltered(self) -> bool: ...
    @property
    def only(self) -> bool: ...

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
class SafeSql:
    """SQL that is safe to run, and what it is."""

    @property
    def sql(self) -> str:
        """The SQL to send to the database."""
    @property
    def params(self) -> list[str]:
        """Values for the placeholders p14g added, in order. Empty unless the policy uses `literals='params'`.

        The first is numbered one above the highest placeholder in the input, so append these to the
        parameters the input already needed.
        """
    @property
    def kind(self) -> _Kind: ...
    @property
    def tables(self) -> list[str]:
        """The tables and views the statement uses, as it named them, sorted."""

@final
class Policy(Generic[_C]):
    """A set of rules that untrusted SQL is checked against. Build it once and reuse it.

    A statement that no rule allows is rejected.

    Args:
        rules: What may be read and written.
        functions: Functions to allow on top of the defaults, as `name` or `schema.name`. Please be extremely
            careful about adding extra functions here unless you know exactly what they do: one that changes a
            setting, runs SQL given as text, or is `SECURITY DEFINER` can change the role the statement runs as or
            get round the policy. `DANGEROUS_FUNCTIONS.md` lists some known dangerous functions; it is not
            exhaustive.
        deny_functions: Functions to forbid that would otherwise be allowed.
        default_functions: Whether to start from `DEFAULT_FUNCTIONS`.
        operators: The operators a statement may use, on any table and on none.
            The default is everything except regular expressions (`~` and `similar to`).
        star_behaviour: What to do with `*`. `expand` replaces it with the columns the rule lists, `reject`
            refuses it.
        literals: `inline` writes string literals into the SQL, escaped. `params` replaces them with
            placeholders and returns the values in `SafeSql.params`.
        quote_identifiers: `minimal` puts double quotes only around names that need them: anything that is not
            plain lower case, and Postgres keywords where they are not after a dot. `always` quotes every name.
        layout: `multiline` writes each clause of the statement on its own line, `dense` writes one line.
        max_rows: Cap on the rows a `SELECT` returns: a missing `LIMIT` is added and a larger one reduced.
        default_schema: The schema that unqualified table names belong to, in rules and in statements. Without it
            they are written unqualified and Postgres resolves them through the `search_path`.
        dialect: The dialect of the input: `postgres`, `generic`, `ansi`, `mysql` or `sqlite`.
        limits: Bounds on the size of a statement.
    """

    def __new__(
        cls,
        *rules: Select[_C] | Insert[_C] | Update[_C] | Delete[_C],
        functions: Sequence[str] | None = None,
        deny_functions: Sequence[str] | None = None,
        default_functions: bool = True,
        operators: Sequence[_Operator] | None = None,
        star_behaviour: _Literal['expand', 'reject'] = 'expand',
        literals: _Literal['inline', 'params'] = 'inline',
        quote_identifiers: _Literal['minimal', 'always'] = 'minimal',
        layout: _Literal['multiline', 'dense'] = 'multiline',
        max_rows: int | None = None,
        default_schema: str | None = None,
        dialect: _Literal['postgres', 'generic', 'ansi', 'mysql', 'sqlite'] = 'postgres',
        limits: Limits | None = None,
    ) -> Policy[_C]: ...
    @overload
    def grants(self: Policy[None], role: str, *, context: None = None) -> list[str]:
        """The `GRANT` statements that give `role` the table access this policy allows.

        Run them once as the owner of the tables, for the role that will run p14g's output, so that the database
        enforces the same rules. `context` is passed to `extra` callables to learn which columns they set.

        Grants cannot say everything a policy does, so they allow somewhat more: the columns of several rules for
        one table are combined, functions and operators are not restricted, and `only` has no equivalent.
        `USAGE` on sequences that inserted rows take defaults from is not included.
        """
    @overload
    def grants(self, role: str, *, context: _C) -> list[str]: ...
    @overload
    def rewrite(self: Policy[None], sql: str, *, context: None = None, allow: Sequence[_Kind] | None = None) -> SafeSql:
        """Check one SQL statement against the policy and return it rewritten so it is safe to run.

        Raises `P14gError` if the statement is not allowed.

        `context` is passed on to `filter` and `extra` callables. `allow` restricts the kinds of statement
        accepted by this call, for example `['select']`.
        """
    @overload
    def rewrite(self, sql: str, *, context: _C, allow: Sequence[_Kind] | None = None) -> SafeSql: ...
