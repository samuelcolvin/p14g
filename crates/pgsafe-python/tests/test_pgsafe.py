from __future__ import annotations

from typing import Any

import pgsafe
import pytest
from pgsafe import (
    Column,
    Delete,
    Expr,
    Function,
    Insert,
    Limits,
    Literal,
    PgSafeError,
    Policy,
    Select,
    Table,
    Update,
    mapper,
)


def add_tenant(context: dict[str, Any]) -> dict[str, Any]:
    return {'tenant_id': context['tenant_id'], 'created_by': context['user']}


@pytest.fixture(name='policy')
def fixture_policy() -> Policy:
    return Policy(
        Select('orders', columns=['id', 'product', 'qty']),
        Select('v'),
        Insert('orders', columns=['product', 'qty'], extra=add_tenant),
        Update('orders', columns=['qty']),
        Delete('orders'),
    )


def test_select(policy: Policy):
    safe = policy.rewrite('select id from orders where qty < 3')
    assert safe.sql == 'SELECT "orders"."id" FROM "orders" WHERE ("orders"."qty" < 3)'
    assert safe.params == []
    assert safe.kind == 'select'
    assert safe.tables == ['orders']
    assert repr(safe) == (
        'SafeSql(sql="SELECT \\"orders\\".\\"id\\" FROM \\"orders\\" WHERE (\\"orders\\".\\"qty\\" < 3)", '
        'params=[], kind="select", tables=["orders"])'
    )


def test_star_is_expanded(policy: Policy):
    assert policy.rewrite('select * from orders').sql == (
        'SELECT "orders"."id", "orders"."product", "orders"."qty" FROM "orders"'
    )
    assert policy.rewrite('select * from v').sql == 'SELECT "v".* FROM "v"'


@pytest.mark.parametrize(
    'sql,kind,message',
    [
        ('select * from pg_shadow', 'denied', 'reading from table "pg_shadow" is not allowed'),
        ('select secret from orders', 'denied', 'column "secret" is not allowed'),
        ('select pg_sleep(10)', 'denied', 'function "pg_sleep" is not allowed'),
        ('select id from orders; drop table orders', 'parse', 'expected exactly one SQL statement, found several'),
        ('drop table orders', 'unsupported', 'only SELECT, INSERT, UPDATE and DELETE statements are supported'),
        ('select id from orders for update', 'unsupported', 'FOR UPDATE / FOR SHARE is not supported'),
        ('delete from orders', 'denied', 'DELETE from table "orders" without a WHERE clause is not allowed'),
        ("select id from orders where product ~ 'x'", 'denied', 'operator not allowed on table "orders": ~'),
    ],
)
def test_rejected(policy: Policy, sql: str, kind: str, message: str):
    with pytest.raises(PgSafeError) as exc_info:
        policy.rewrite(sql)
    error = exc_info.value
    assert error.kind == kind
    assert error.message == message
    assert isinstance(error, ValueError)
    assert kind in pgsafe.ERROR_KINDS


def test_error_position(policy: Policy):
    with pytest.raises(PgSafeError) as exc_info:
        policy.rewrite("select id,\n  U&'x'\nfrom orders")
    error = exc_info.value
    assert str(error) == 'this kind of literal is not supported at line 2, column 3'
    assert error.message == 'this kind of literal is not supported'
    assert (error.line, error.column) == (2, 3)

    with pytest.raises(PgSafeError) as exc_info:
        policy.rewrite('select secret from orders')
    assert (exc_info.value.line, exc_info.value.column) == (None, None)


def test_injection_stays_a_literal(policy: Policy):
    sql = r"select id from orders where product = 'x\'' UNION SELECT password FROM users --'"
    assert policy.rewrite(sql).sql == (
        r"""SELECT "orders"."id" FROM "orders" WHERE ("orders"."product" = E'x\\'' UNION SELECT password FROM users --')"""
    )


def test_insert_extra_callable(policy: Policy):
    safe = policy.rewrite(
        "insert into orders (product, qty) values ('tea', 2)", context={'tenant_id': 42, 'user': 'sam'}
    )
    assert safe.sql == (
        'INSERT INTO "orders" ("product", "qty", "tenant_id", "created_by") VALUES (\'tea\', 2, 42, \'sam\')'
    )
    assert safe.kind == 'insert'
    assert safe.tables == ['orders']


def test_insert_extra_dict_and_values():
    policy = Policy(
        Insert(
            't',
            extra={
                'a': None,
                'b': True,
                'c': -5,
                'd': 1.5,
                'e': "it's",
                'f': 10**30,
                'g': float('inf'),
                'h': -0.0,
                'i': 2.0,
            },
        )
    )
    assert policy.rewrite('insert into t (x) values (1), (2)').sql == (
        'INSERT INTO "t" ("x", "a", "b", "c", "d", "e", "f", "g", "h", "i") VALUES '
        "(1, NULL, TRUE, (- 5), 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0.0, 2.0), "
        "(2, NULL, TRUE, (- 5), 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0.0, 2.0)"
    )


def test_insert_extra_collision(policy: Policy):
    context = {'tenant_id': 42, 'user': 'sam'}
    # the rule lists the columns a statement may set, and `tenant_id` is not one of them
    with pytest.raises(PgSafeError, match='inserting into these columns of table "orders" is not allowed: tenant_id'):
        policy.rewrite("insert into orders (product, tenant_id) values ('tea', 1)", context=context)

    # a rule that allows any column still refuses the ones the policy sets
    open_policy = Policy(Insert('orders', extra=add_tenant))
    with pytest.raises(PgSafeError, match='is set by the policy and cannot be set by the statement') as exc_info:
        open_policy.rewrite("insert into orders (product, tenant_id) values ('tea', 1)", context=context)
    assert exc_info.value.kind == 'denied'


def test_insert_extra_raises(policy: Policy):
    with pytest.raises(PgSafeError) as exc_info:
        policy.rewrite("insert into orders (product, qty) values ('tea', 2)", context={})
    error = exc_info.value
    assert error.kind == 'callback'
    assert str(error) == "callback failed: KeyError: 'tenant_id'"
    assert isinstance(error.__cause__, KeyError)


def returns_str(context: Any) -> Any:
    return 'nope'


def returns_int_keys(context: Any) -> Any:
    return {1: 2}


def returns_object_values(context: Any) -> Any:
    return {'a': object()}


@pytest.mark.parametrize('extra', [returns_str, returns_int_keys, returns_object_values])
def test_insert_extra_bad_return(extra: Any):
    policy = Policy(Insert('t', extra=extra))
    with pytest.raises(PgSafeError) as exc_info:
        policy.rewrite('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'
    assert isinstance(exc_info.value.__cause__, TypeError)


def test_insert_extra_bad_column():
    policy = Policy(Insert('t', extra={'': 1}))
    with pytest.raises(PgSafeError, match='extra returned an invalid column') as exc_info:
        policy.rewrite('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'

    with pytest.raises(TypeError, match='extra must be a dict or a callable returning a dict'):
        Insert('t', extra=[('a', 1)])  # pyright: ignore[reportArgumentType]


def test_update_and_delete(policy: Policy):
    safe = policy.rewrite('update orders set qty = qty + 1 where id = 5 returning *')
    assert safe.sql == (
        'UPDATE "orders" SET "qty" = ("orders"."qty" + 1) WHERE ("orders"."id" = 5) '
        'RETURNING "orders"."id", "orders"."product", "orders"."qty"'
    )
    assert safe.kind == 'update'
    safe = policy.rewrite('delete from orders where id = 1')
    assert safe.sql == 'DELETE FROM "orders" WHERE ("orders"."id" = 1)'
    assert safe.kind == 'delete'

    unfiltered = Policy(Update('orders', allow_unfiltered=True), Delete('orders', allow_unfiltered=True))
    assert unfiltered.rewrite('update orders set qty = 1').sql == 'UPDATE "orders" SET "qty" = 1'
    assert unfiltered.rewrite('delete from orders').sql == 'DELETE FROM "orders"'


def test_allow(policy: Policy):
    assert policy.rewrite('select id from orders', allow=['select']).kind == 'select'
    with pytest.raises(PgSafeError, match='DELETE statements are not allowed here'):
        policy.rewrite('delete from orders where id = 1', allow=['select', 'insert'])
    with pytest.raises(PgSafeError, match='unknown statement kind "merge"') as exc_info:
        policy.rewrite('select 1', allow=['merge'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'


def test_functions():
    policy = Policy(Select('orders'), functions=['app.order_total'], deny_functions=['random', 'now'])
    assert policy.rewrite('select app.order_total(id), lower(product) from orders').sql == (
        'SELECT "app"."order_total"("orders"."id"), pg_catalog."lower"("orders"."product") FROM "orders"'
    )
    for sql in 'select random()', 'select now()', 'select order_total(1)':
        with pytest.raises(PgSafeError, match='is not allowed'):
            policy.rewrite(sql)

    with pytest.raises(PgSafeError, match='cannot deny function "pg_sleep": it is not an allowed function'):
        Policy(deny_functions=['pg_sleep'])

    bare = Policy(Select('orders'), default_functions=False)
    with pytest.raises(PgSafeError, match='function "count" is not allowed'):
        bare.rewrite('select count(*) from orders')

    assert 'count' in pgsafe.DEFAULT_FUNCTIONS
    assert 'pg_sleep' not in pgsafe.DEFAULT_FUNCTIONS
    assert isinstance(pgsafe.DEFAULT_FUNCTIONS, frozenset)


def test_operators():
    policy = Policy(Select('orders', operators=['=', 'and']), Select('other'), operators=['<', '~'])
    assert policy.rewrite('select id from orders where id = 1 and qty = 2').kind == 'select'
    with pytest.raises(PgSafeError, match='operator not allowed on table "orders": <'):
        policy.rewrite('select id from orders where id < 1')
    assert policy.rewrite("select id from other where id < 1 and name ~ 'x'".replace(' and ', ' < ')).kind == 'select'

    with pytest.raises(PgSafeError, match='unknown operator "xor"') as exc_info:
        Select('orders', operators=['xor'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'
    with pytest.raises(PgSafeError, match='unknown operator "xor"'):
        Policy(operators=['xor'])  # pyright: ignore[reportArgumentType]


def test_star_behaviour():
    with pytest.raises(PgSafeError, match=r'\* is not allowed, list the columns'):
        Policy(Select('v'), star_behaviour='reject').rewrite('select * from v')
    allow = Policy(Select('v'), Select('orders', columns=['id']), star_behaviour='allow')
    assert allow.rewrite('select * from v').sql == 'SELECT * FROM "v"'
    with pytest.raises(PgSafeError, match='only some of its columns are allowed'):
        allow.rewrite('select * from orders')
    with pytest.raises(PgSafeError, match='unknown star behaviour "maybe"'):
        Policy(star_behaviour='maybe')  # pyright: ignore[reportArgumentType]


def test_params():
    policy = Policy(Select('orders'), literals='params')
    safe = policy.rewrite("select id from orders where product = 'tea' and qty = $1 and note = 'it''s'")
    assert safe.sql == (
        'SELECT "orders"."id" FROM "orders" '
        'WHERE ((("orders"."product" = $2) AND ("orders"."qty" = $1)) AND ("orders"."note" = $3))'
    )
    assert safe.params == ['tea', "it's"]
    with pytest.raises(PgSafeError, match='unknown literals mode "bind"'):
        Policy(literals='bind')  # pyright: ignore[reportArgumentType]


def test_max_rows_dialect_limits():
    policy = Policy(Select('orders'), max_rows=10)
    assert policy.rewrite('select id from orders').sql == 'SELECT "orders"."id" FROM "orders" LIMIT 10'
    assert policy.rewrite('select id from orders limit 3').sql == 'SELECT "orders"."id" FROM "orders" LIMIT 3'

    mysql = Policy(Select('orders'), dialect='mysql')
    assert mysql.rewrite('select `id` from `orders`').sql == 'SELECT "orders"."id" FROM "orders"'
    with pytest.raises(PgSafeError, match='unknown dialect "oracle"'):
        Policy(dialect='oracle')  # pyright: ignore[reportArgumentType]

    limits = Limits(max_sql_bytes=30, max_joins=0)
    assert limits.max_sql_bytes == 30
    assert limits.max_joins == 0
    assert limits.max_depth == 50
    assert repr(limits).startswith('Limits(max_sql_bytes=30, max_depth=50, ')
    tight = Policy(Select('orders'), limits=limits)
    with pytest.raises(PgSafeError, match='SQL is 38 bytes, the limit is 30') as exc_info:
        tight.rewrite('select id from orders where qty > 1000')
    assert exc_info.value.kind == 'limit'
    with pytest.raises(PgSafeError, match='max_depth must be at least 1'):
        Policy(limits=Limits(max_depth=0))


def test_rules():
    select = Select('orders', columns=('id', 'qty'), operators=['='])
    assert (select.table, select.columns, select.operators) == ('orders', ['id', 'qty'], ['='])
    assert repr(select) == 'Select("orders", columns=["id", "qty"], operators=["="], only=False)'
    assert repr(Select('v')) == 'Select("v", columns=None, operators=None, only=False)'
    insert = Insert('orders', columns=['id'])
    assert (insert.table, insert.columns) == ('orders', ['id'])
    assert repr(insert) == 'Insert("orders", columns=["id"])'
    update = Update('orders', columns=['qty'], allow_unfiltered=True)
    assert (update.table, update.columns, update.allow_unfiltered) == ('orders', ['qty'], True)
    assert repr(update) == 'Update("orders", columns=["qty"], allow_unfiltered=True, only=False)'
    delete = Delete('orders')
    assert (delete.table, delete.allow_unfiltered) == ('orders', False)
    assert repr(delete) == 'Delete("orders", allow_unfiltered=False, only=False)'

    with pytest.raises(TypeError, match='a rule must be a Select, Insert, Update or Delete, not str'):
        Policy('orders')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        Select('orders', columns='id')
    with pytest.raises(PgSafeError, match='invalid table name "a.b.c"') as exc_info:
        Policy(Select('a.b.c'))
    assert exc_info.value.kind == 'config'


def test_table_mapper():
    seen: list[Any] = []

    @mapper(Table)
    def per_tenant(table: Table, context: Any) -> Table:
        seen.append((table, context))
        if table.name == 'events':
            return Table(f'events_{context}', schema='tenants', alias=table.alias)
        return table

    policy = Policy(Select('events'), Select('other'), Insert('events'), mappers=[per_tenant])
    safe = policy.rewrite('select e.id, other.x from events e join other on other.id = e.id', context=42)
    assert safe.sql == (
        'SELECT "e"."id", "other"."x" FROM "tenants"."events_42" AS "e" INNER JOIN "other" ON ("other"."id" = "e"."id")'
    )
    # the tables are reported as the statement named them
    assert safe.tables == ['events', 'other']
    assert seen == [(Table('events', alias='e'), 42), (Table('other'), 42)]

    # without an alias, the original name is kept as one so that the columns still resolve
    assert policy.rewrite('select id from events', context=7).sql == (
        'SELECT "events"."id" FROM "tenants"."events_7" AS "events"'
    )
    assert policy.rewrite('insert into events (a) values (1) returning a', context=7).sql == (
        'INSERT INTO "tenants"."events_7" AS "events" ("a") VALUES (1) RETURNING "events"."a"'
    )
    # the decorated function can still be called directly
    assert per_tenant(Table('events'), 1) == Table('events_1', schema='tenants')
    assert repr(per_tenant).startswith('<Mapper of Table <function test_table_mapper.<locals>.per_tenant')


def test_expression_mappers():
    @mapper(Function)
    def freeze_time(function: Function, context: Any) -> pgsafe.ExprLike:
        if function.name == 'now':
            return function.replace(name='frozen_now', schema='app')
        if function.name == 'lower':
            # arguments can be passed on without knowing what they are
            return Function('upper', function.args)
        return function

    @mapper(Literal)
    def redact(literal: Literal, context: Any) -> pgsafe.ExprLike:
        return None if literal.value == 'secret' else literal

    @mapper(Column)
    def day(column: Column, context: Any) -> pgsafe.ExprLike:
        if column.name == 'created':
            return Function('date_trunc', ['day', column])
        return column

    policy = Policy(Select('v'), mappers=[freeze_time, redact, day])
    assert policy.rewrite("select created, lower(a || 'x') from v where b = 'secret' and c < now()").sql == (
        'SELECT pg_catalog."date_trunc"(\'day\', "v"."created"), pg_catalog."upper"(("v"."a" || \'x\')) '
        'FROM "v" WHERE (("v"."b" = NULL) AND ("v"."c" < "app"."frozen_now"()))'
    )

    # modifiers survive `replace`
    @mapper(Function)
    def rename_count(function: Function, context: Any) -> pgsafe.ExprLike:
        return function.replace(name='my_count', schema=None) if function.name == 'count' else function

    policy = Policy(Select('v'), mappers=[rename_count])
    assert policy.rewrite('select count(distinct a) filter (where b > 1) over (partition by c) from v').sql == (
        'SELECT "my_count"(DISTINCT "v"."a") FILTER (WHERE ("v"."b" > 1)) OVER (PARTITION BY "v"."c") FROM "v"'
    )


def test_mapper_errors():
    @mapper(Column)
    def broken(column: Column, context: Any) -> pgsafe.ExprLike:
        raise RuntimeError('no columns today')

    @mapper(Table)
    def not_a_table(table: Table, context: Any) -> Table:
        return 'events'  # pyright: ignore[reportReturnType]

    @mapper(Literal)
    def not_an_expr(literal: Literal, context: Any) -> pgsafe.ExprLike:
        return object()  # pyright: ignore[reportReturnType]

    for mappers, sql, cause, message in [
        ([broken], 'select a from v', RuntimeError, 'callback failed: RuntimeError: no columns today'),
        ([not_a_table], 'select 1 from v', TypeError, 'callback failed: TypeError: a Table mapper must return a Table'),
        (
            [not_an_expr],
            'select 1 from v',
            TypeError,
            'callback failed: TypeError: expected a Column, Function, Literal, Expr, None, bool, int, float or str'
            + ', not object',
        ),
    ]:
        policy = Policy(Select('v'), mappers=mappers)
        with pytest.raises(PgSafeError) as exc_info:
            policy.rewrite(sql)
        assert str(exc_info.value) == message
        assert exc_info.value.kind == 'callback'
        assert isinstance(exc_info.value.__cause__, cause)

    with pytest.raises(TypeError, match=r'mapper\(\) takes Table, Column, Function or Literal'):
        mapper(Expr)  # pyright: ignore[reportArgumentType, reportCallIssue]
    with pytest.raises(TypeError):
        Policy(mappers=[lambda t, c: t])  # pyright: ignore[reportArgumentType, reportUnknownLambdaType]


def test_nodes():
    table = Table('orders', schema='app', alias='o')
    assert (table.name, table.schema, table.alias) == ('orders', 'app', 'o')
    assert repr(table) == 'Table("orders", schema="app", alias="o", only=False)'
    assert table == Table('orders', schema='app', alias='o')
    assert table != Table('orders')

    column = Column('id', table='o')
    assert (column.name, column.table) == ('id', 'o')
    assert repr(column) == 'Column("id", table="o")'
    assert repr(Column('id')) == 'Column("id", table=None)'

    function = Function('lower', [column, 'x', 1, None], schema='app')
    assert (function.name, function.schema) == ('lower', 'app')
    assert function.args == [column, Literal('x'), Literal(1), Literal(None)]
    assert repr(function) == 'Function("lower", schema="app")'
    assert function.replace(schema=None).schema is None
    assert function.replace(name='upper').name == 'upper'
    assert function.replace(args=[]).args == []
    assert function.replace() == function
    with pytest.raises(TypeError, match=r"replace\(\) got an unexpected keyword argument 'nope'"):
        function.replace(nope=1)  # pyright: ignore[reportCallIssue]
    # a negative number is a minus applied to a literal, which is not itself a literal
    assert [type(arg) for arg in Function('abs', [-1]).args] == [Expr]
    assert repr(Function('abs', [-1]).args[0]) == 'Expr(...)'

    for value in None, True, False, 0, 42, 1.5, 1.0, 0.0, 1e300, 1e-7, 'text', '':
        literal = Literal(value)
        assert literal.value == value
        assert type(literal.value) is type(value)
        assert repr(literal) == f'Literal({value!r})'
    assert Literal(10**30).value == '1000000000000000000000000000000'
    with pytest.raises(ValueError, match='a negative or non-finite number is not a single literal'):
        Literal(-1)
    with pytest.raises(TypeError, match='a literal must be None, a bool, an int, a float or a str'):
        Literal(b'bytes')  # pyright: ignore[reportArgumentType]

    with pytest.raises(PgSafeError, match='is longer than 63 bytes'):
        Table('x' * 64)
    with pytest.raises(PgSafeError, match='identifiers may not contain NUL'):
        Column('a\0b')
    with pytest.raises(PgSafeError, match='empty identifiers are not allowed'):
        Function('')


def test_mapper_output_is_still_escaped():
    @mapper(Table)
    def hostile(table: Table, context: Any) -> Table:
        return Table('x"; DROP TABLE orders; --', schema='a"b')

    @mapper(Literal)
    def hostile_literal(literal: Literal, context: Any) -> pgsafe.ExprLike:
        return "'; DROP TABLE orders; --\\"

    policy = Policy(Select('v'), mappers=[hostile, hostile_literal])
    assert policy.rewrite("select a from v where b = 'x'").sql == (
        'SELECT "v"."a" FROM "a""b"."x""; DROP TABLE orders; --" AS "v" '
        """WHERE ("v"."b" = E'''; DROP TABLE orders; --\\\\')"""
    )


def test_version():
    assert isinstance(pgsafe.__version__, str)
    assert pgsafe.__version__.count('.') == 2


def test_nodes_are_hashable():
    assert hash(Table('a', schema='s')) == hash(Table('a', schema='s'))
    assert len({Table('a'), Table('a'), Table('a', alias='x')}) == 2
    assert len({Column('a'), Column('a', table='t'), Column('a')}) == 2
    assert len({Literal(1), Literal(1), Literal('1'), Literal(True), Literal(None)}) == 4
    assert len({Function('f', [1]), Function('f', [1]), Function('f', [2]), Function('f', [1], schema='s')}) == 3
    by_table = {Table('orders'): 'o'}
    assert by_table[Table('orders')] == 'o'


def test_nodes_are_not_equal_to_other_things():
    assert Table('a') != 'a'
    assert Column('a') != Table('a')
    assert Literal(1) != 1
    assert Function('f') != Function('g')
    assert Literal(1) != Literal(1.0)
    assert Literal(True) != Literal(1)


def test_nodes_cannot_be_pickled():
    import copy
    import pickle

    for node in Table('a'), Column('a'), Function('f'), Literal(1), Select('a'), Policy():
        with pytest.raises(TypeError, match='cannot pickle'):
            pickle.dumps(node)
        with pytest.raises(TypeError, match='cannot pickle'):
            copy.deepcopy(node)


def test_nodes_are_immutable():
    for node, attribute in (Table('a'), 'name'), (Column('a'), 'name'), (Select('a'), 'table'), (Limits(), 'max_depth'):
        with pytest.raises(AttributeError):
            setattr(node, attribute, 'x')
    safe = Policy().rewrite('select 1')
    with pytest.raises(AttributeError):
        safe.sql = 'drop table x'  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(TypeError):
        Table()  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match='cannot create'):
        pgsafe.SafeSql()  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match='cannot create'):
        Expr()  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError, match='cannot create'):
        pgsafe.Mapper()  # pyright: ignore[reportCallIssue]


def test_function_args_shapes():
    seen: dict[str, list[Any]] = {}

    @mapper(Function)
    def record(function: Function, context: Any) -> pgsafe.ExprLike:
        seen[function.name] = function.args
        return function

    policy = Policy(Select('v'), mappers=[record])
    sql = "select count(*), current_date, now(), lower(a), coalesce(b, -1, 'x', c + 1, (select max(d) from v)) from v"
    out = policy.rewrite(sql).sql
    # a mapper that returns what it was given changes nothing
    assert out == Policy(Select('v')).rewrite(sql).sql
    assert seen['count'] == []
    assert seen['now'] == []
    assert seen['lower'] == [Column('a', table='v')]
    # COALESCE and CURRENT_DATE are grammar, not functions: the mapper is not called for them, only for the
    # function inside the COALESCE
    assert set(seen) == {'count', 'now', 'lower', 'max'}
    assert seen['max'] == [Column('d', table='v')]

    # `f(*)` has no argument list to replace, so giving it one makes an ordinary call
    @mapper(Function)
    def count_one(function: Function, context: Any) -> pgsafe.ExprLike:
        return function.replace(args=[1]) if function.name == 'count' else function

    assert Policy(Select('v'), mappers=[count_one]).rewrite('select count(*) from v').sql == (
        'SELECT pg_catalog."count"(1) FROM "v"'
    )


def test_mappers_run_in_order_and_bottom_up():
    calls: list[str] = []

    @mapper(Function)
    def first(function: Function, context: Any) -> pgsafe.ExprLike:
        calls.append(f'first:{function.name}')
        return function.replace(name='abs') if function.name == 'lower' else function

    @mapper(Function)
    def second(function: Function, context: Any) -> pgsafe.ExprLike:
        calls.append(f'second:{function.name}')
        return function

    @mapper(Function)
    def to_literal(function: Function, context: Any) -> pgsafe.ExprLike:
        return 7 if function.name == 'upper' else function

    @mapper(Literal)
    def never_sees_mapped_output(literal: Literal, context: Any) -> pgsafe.ExprLike:
        calls.append(f'literal:{literal.value}')
        return literal

    policy = Policy(Select('v'), mappers=[first, second, to_literal, never_sees_mapped_output])
    assert policy.rewrite('select lower(upper(a)), 1 from v').sql == 'SELECT pg_catalog."abs"(7), 1 FROM "v"'
    # the inner call is mapped before the outer one, and each mapper is given what the one before returned,
    # so the literal mapper sees the literal that replaced `upper(a)`
    assert calls == ['first:upper', 'second:upper', 'literal:7', 'first:lower', 'second:abs', 'literal:1']


def test_mapper_everywhere_in_a_statement():
    @mapper(Literal)
    def bump(literal: Literal, context: Any) -> pgsafe.ExprLike:
        return literal.value + 1 if isinstance(literal.value, int) and not isinstance(literal.value, bool) else literal

    policy = Policy(Select('v'), Insert('v'), Update('v'), Delete('v'), mappers=[bump])
    assert policy.rewrite(
        'with c as (select 1 as n from v) select a, case when b = 1 then 2 else 3 end from v join c on c.n = 1 '
        'where a in (1, 2) and b between 1 and 2 and exists (select 1 from v where a = 1) '
        'group by a, b having count(*) > 1 order by a + 1 limit 1 offset 1'
    ).sql == (
        'WITH "c" AS (SELECT 2 AS "n" FROM "v") SELECT "v"."a", (CASE WHEN ("v"."b" = 2) THEN 3 ELSE 4 END) '
        'FROM "v" INNER JOIN "c" ON ("c"."n" = 2) '
        'WHERE ((("v"."a" IN (2, 3)) AND ("v"."b" BETWEEN 2 AND 3)) AND (EXISTS (SELECT 2 FROM "v" WHERE ("v"."a" = 2)))) '
        'GROUP BY "v"."a", "v"."b" HAVING (pg_catalog."count"(*) > 2) ORDER BY ("v"."a" + 2) LIMIT 2 OFFSET 2'
    )
    assert policy.rewrite('insert into v (a) values (1), (2) returning a + 1').sql == (
        'INSERT INTO "v" ("a") VALUES (2), (3) RETURNING ("v"."a" + 2)'
    )
    assert policy.rewrite('update v set a = 1 where b = 1 returning 1').sql == (
        'UPDATE "v" SET "a" = 2 WHERE ("v"."b" = 2) RETURNING 2'
    )
    assert policy.rewrite('delete from v where b = 1').sql == 'DELETE FROM "v" WHERE ("v"."b" = 2)'
    assert policy.rewrite('select a from v union select a from v where a = 1 order by 1').sql == (
        '(SELECT "v"."a" FROM "v") UNION (SELECT "v"."a" FROM "v" WHERE ("v"."a" = 2)) ORDER BY 1'
    )


def test_mapper_returns_opaque_expr():
    @mapper(Function)
    def unwrap(function: Function, context: Any) -> pgsafe.ExprLike:
        # replace `lower(x)` with `x`, whatever `x` is
        return function.args[0] if function.name == 'lower' else function

    policy = Policy(Select('v'), mappers=[unwrap])
    assert policy.rewrite('select lower(a + 1), lower(b), lower(-2) from v').sql == (
        'SELECT ("v"."a" + 1), "v"."b", (- 2) FROM "v"'
    )


def test_keyword_forms_as_arguments():
    seen: list[Any] = []

    @mapper(Function)
    def record(function: Function, context: Any) -> pgsafe.ExprLike:
        seen.extend(function.args)
        return function

    policy = Policy(Select('v'), mappers=[record])
    sql = 'select concat(coalesce(a, 1), nullif(a, 1), greatest(a, 1), current_date, trim(a), extract(year from b)) from v'
    assert policy.rewrite(sql).sql == (
        'SELECT pg_catalog."concat"(COALESCE("v"."a", 1), NULLIF("v"."a", 1), GREATEST("v"."a", 1), CURRENT_DATE, '
        'TRIM(BOTH FROM "v"."a"), EXTRACT(YEAR FROM "v"."b")) FROM "v"'
    )
    # each arrives as an opaque expression, which can be passed on but not taken apart
    assert [type(arg) for arg in seen] == [Expr] * 6


def test_mapper_builds_invalid_sql():
    @mapper(Column)
    def constant(column: Column, context: Any) -> pgsafe.ExprLike:
        return 'x' if column.name == 'b' else column

    policy = Policy(Select('v'), mappers=[constant])
    assert policy.rewrite('select a from v where b = a').sql == """SELECT "v"."a" FROM "v" WHERE ('x' = "v"."a")"""
    # Postgres rejects a bare constant in ORDER BY and GROUP BY, so pgsafe will not write one
    for sql, clause in ('select a from v order by b', 'ORDER BY'), ('select count(*) from v group by b', 'GROUP BY'):
        with pytest.raises(PgSafeError, match=f'a constant that is not a column position in {clause}') as exc_info:
            policy.rewrite(sql)
        assert exc_info.value.kind == 'unsupported'

    # a function named after a keyword form is an ordinary call, which Postgres will say does not exist
    @mapper(Function)
    def not_a_keyword(function: Function, context: Any) -> pgsafe.ExprLike:
        return Function('nullif', [1])

    assert Policy(Select('v'), mappers=[not_a_keyword]).rewrite('select lower(a) from v').sql == (
        'SELECT pg_catalog."nullif"(1) FROM "v"'
    )


def test_context_is_passed_through_unchanged():
    marker = object()
    seen: list[Any] = []

    @mapper(Table)
    def table(table: Table, context: Any) -> Table:
        seen.append(context)
        return table

    def extra(context: Any) -> dict[str, Any]:
        seen.append(context)
        return {}

    policy = Policy(Select('t'), Insert('t', extra=extra), mappers=[table])
    policy.rewrite('insert into t (a) values (1)', context=marker)
    assert seen == [marker, marker]
    seen.clear()
    policy.rewrite('select a from t')
    assert seen == [None]


def test_extra_is_called_once_per_check():
    calls = 0

    def extra(context: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {'n': calls}

    policy = Policy(Insert('t', extra=extra))
    assert policy.rewrite('insert into t (a) values (1), (2), (3)').sql == (
        'INSERT INTO "t" ("a", "n") VALUES (1, 1), (2, 1), (3, 1)'
    )
    assert calls == 1
    # not called for a statement that is rejected before the rule is reached
    with pytest.raises(PgSafeError):
        policy.rewrite('insert into other (a) values (1)')
    assert calls == 1


def test_extra_values():
    policy = Policy(
        Insert(
            't',
            extra={'col': Column('x'), 'fn': Function('now'), 'lit': Literal('s'), 'neg': -1.5, 'nan': float('nan')},
        )
    )
    assert policy.rewrite('insert into t (a) values (1)').sql == (
        'INSERT INTO "t" ("a", "col", "fn", "lit", "neg", "nan") '
        'VALUES (1, "x", pg_catalog."now"(), \'s\', (- 1.5), CAST(\'NaN\' AS double precision))'
    )
    params = Policy(Insert('t', extra={'s': 'from policy'}), literals='params')
    safe = params.rewrite("insert into t (a) values ('x')")
    assert safe.sql == 'INSERT INTO "t" ("a", "s") VALUES ($1, $2)'
    assert safe.params == ['x', 'from policy']
    with pytest.raises(TypeError, match='expected a Column, Function, Literal, Expr, None, bool, int, float or str'):
        Insert('t', extra={'a': b'bytes'})  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match='the keys of extra must be column names'):
        Insert('t', extra={1: 'a'})  # pyright: ignore[reportArgumentType]


def test_policy_can_be_used_from_a_callback():
    inner = Policy(Select('v'))

    @mapper(Literal)
    def nested(literal: Literal, context: Any) -> pgsafe.ExprLike:
        if literal.value == 'sql':
            return inner.rewrite('select a from v').sql
        return literal

    outer = Policy(Select('v'), mappers=[nested])
    assert outer.rewrite("select 'sql' from v").sql == """SELECT 'SELECT "v"."a" FROM "v"' FROM "v\""""

    # and a policy can check from inside its own mapper
    policies: list[Policy] = []

    @mapper(Table)
    def recursive(table: Table, context: Any) -> Table:
        if context == 0:
            return table
        return Table(policies[0].rewrite('select 1 from v', context=context - 1).kind)

    policies.append(Policy(Select('v'), mappers=[recursive]))
    assert policies[0].rewrite('select a from v', context=3).sql == 'SELECT "v"."a" FROM "select" AS "v"'


def test_threads():
    from concurrent.futures import ThreadPoolExecutor

    def extra(context: int) -> dict[str, int]:
        return {'n': context}

    @mapper(Table)
    def suffix(table: Table, context: int) -> Table:
        return Table(f'{table.name}_{context}')

    policy = Policy(Select('t', columns=['a']), Insert('t', extra=extra), mappers=[suffix])

    def work(n: int) -> list[str]:
        out: list[str] = []
        for _ in range(200):
            out.append(policy.rewrite('select * from t where a = 1', context=n).sql)
            out.append(policy.rewrite('insert into t (a) values (1)', context=n).sql)
            with pytest.raises(PgSafeError):
                policy.rewrite('select b from t', context=n)
        return out

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(work, range(16)))
    for n, result in enumerate(results):
        assert set(result) == {
            f'SELECT "t"."a" FROM "t_{n}" AS "t" WHERE ("t"."a" = 1)',
            f'INSERT INTO "t_{n}" AS "t" ("a", "n") VALUES (1, {n})',
        }


def test_check_arguments():
    policy = Policy(Select('v'))
    with pytest.raises(TypeError):
        policy.rewrite(b'select 1')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        policy.rewrite('select 1', 'context')  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError):
        policy.rewrite('select 1', allow='select')  # pyright: ignore[reportArgumentType]
    with pytest.raises(PgSafeError, match='SELECT statements are not allowed here'):
        policy.rewrite('select 1', allow=[])
    assert policy.rewrite('SELECT 1', allow=['SELECT', 'Insert']).kind == 'select'  # pyright: ignore[reportArgumentType]
    # the input is unicode, not bytes: a lone surrogate cannot be encoded
    with pytest.raises(UnicodeEncodeError):
        policy.rewrite("select '\ud800'")
    assert policy.rewrite("select 'café \U0001f600'").sql == "SELECT 'café \U0001f600'"
    with pytest.raises(PgSafeError, match='string literals may not contain NUL'):
        policy.rewrite("select 'a\0b'")


def test_policy_arguments():
    with pytest.raises(TypeError):
        Policy(functions='count')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        Policy(limits={'max_depth': 1})  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        Policy(Select('v'), Select)  # pyright: ignore[reportArgumentType]
    with pytest.raises((TypeError, OverflowError)):
        Policy(max_rows=-1)
    with pytest.raises((TypeError, OverflowError)):
        Limits(max_depth=-1)
    # an empty policy allows statements that touch no table
    empty = Policy()
    assert empty.rewrite('select 1 + 1, lower($1)').sql == 'SELECT (1 + 1), pg_catalog."lower"($1)'
    assert empty.rewrite('select 1').tables == []


def test_all_limits():
    defaults = Limits()
    assert (
        defaults.max_sql_bytes,
        defaults.max_depth,
        defaults.max_nodes,
        defaults.max_joins,
        defaults.max_subqueries,
        defaults.max_set_operations,
        defaults.max_in_list,
        defaults.max_projection,
        defaults.max_values_rows,
    ) == (65536, 50, 10000, 8, 16, 8, 1000, 200, 1000)

    def rejected(sql: str, **limits: int) -> str:
        policy = Policy(Select('v'), Insert('v'), limits=Limits(**limits))
        with pytest.raises(PgSafeError) as exc_info:
            policy.rewrite(sql)
        assert exc_info.value.kind == 'limit'
        return exc_info.value.message

    assert rejected('select ((((a)))) from v', max_depth=4) == 'SQL is nested too deeply'
    assert rejected('select a, b, c from v', max_nodes=5) == 'SQL has 8 tokens, the limit is 5'
    assert rejected('select v.a from v join v x on true', max_joins=0) == 'SQL has more than 0 joins'
    assert rejected('select (select 1) from v', max_subqueries=0) == 'SQL has more than 0 subqueries'
    assert rejected('select 1 union select 2', max_set_operations=0) == 'SQL has more than 0 set operations'
    assert rejected('select a from v where a in (1, 2)', max_in_list=1) == 'IN list has more than 1 items'
    assert rejected('select a, b from v', max_projection=1) == 'select list has more than 1 items'
    assert rejected('insert into v (a) values (1), (2)', max_values_rows=1) == 'INSERT has more than 1 rows'


def test_expr_like_alias():
    import typing

    assert set(typing.get_args(pgsafe.ExprLike)) == {Column, Function, Literal, Expr, type(None), bool, int, float, str}
    public = {name for name in dir(pgsafe) if not name.startswith('_') and name != 'pgsafe'}
    assert set(pgsafe.__all__) == public | {'__version__'}


def test_error_is_a_normal_exception():
    error = PgSafeError('message')
    assert str(error) == 'message'
    assert not hasattr(error, 'kind')
    try:
        Policy().rewrite('select * from t')
    except ValueError as e:
        assert isinstance(e, PgSafeError)
        assert e.args == ('reading from table "t" is not allowed',)
        assert e.__cause__ is None


def test_nodes_have_no_order():
    pairs: list[list[Any]] = [
        [Table('a'), Table('b')],
        [Column('a'), Column('b')],
        [Literal(1), Literal(2)],
        [Function('a'), Function('b')],
    ]
    for pair in pairs:
        with pytest.raises(TypeError, match="'<' not supported"):
            sorted(pair)


def test_opaque_expr():
    first, second, third = Function('f', [-1, -1, -2]).args
    assert isinstance(first, Expr)
    assert first == second
    assert first != third
    assert hash(first) == hash(second)
    assert first != -1


def test_mapper_repr():
    def f(node: Any, context: Any) -> Any:
        return node

    for kind in Table, Column, Function, Literal:
        assert repr(mapper(kind)(f)).startswith(f'<Mapper of {kind.__name__} <function test_mapper_repr.<locals>.f')


def test_only():
    policy = Policy(
        Select('family', columns=['id'], only=True),
        Update('family', only=True),
        Delete('family', only=True),
        Insert('family'),
        Select('orders'),
        Update('orders'),
    )
    assert policy.rewrite('select * from family f where id = 1').sql == (
        'SELECT "f"."id" FROM ONLY "family" AS "f" WHERE ("f"."id" = 1)'
    )
    assert policy.rewrite('update family set name = 1 where id = 1').sql == (
        'UPDATE ONLY "family" SET "name" = 1 WHERE ("family"."id" = 1)'
    )
    assert (
        policy.rewrite('delete from family where id = 1').sql == 'DELETE FROM ONLY "family" WHERE ("family"."id" = 1)'
    )
    # INSERT has no ONLY: a row goes into the table it names
    assert policy.rewrite('insert into family (id) values (1) returning id').sql == (
        'INSERT INTO "family" ("id") VALUES (1) RETURNING "family"."id"'
    )
    # a statement can ask for ONLY on any table, and its absence on a table the policy marks changes nothing
    assert policy.rewrite('select id from only orders').sql == 'SELECT "orders"."id" FROM ONLY "orders"'
    assert policy.rewrite('update only orders set qty = 1 where id = 1').sql == (
        'UPDATE ONLY "orders" SET "qty" = 1 WHERE ("orders"."id" = 1)'
    )
    assert policy.rewrite('select id from orders').sql == 'SELECT "orders"."id" FROM "orders"'
    assert policy.rewrite('select id from only family').sql == 'SELECT "family"."id" FROM ONLY "family"'

    rules = Select('t', only=True), Update('t', only=True), Delete('t', only=True)
    assert [rule.only for rule in rules] == [True, True, True]
    assert repr(rules[2]) == 'Delete("t", allow_unfiltered=False, only=True)'
    assert not Select('t').only

    for mismatched in (
        [Select('t', only=True), Select('t')],
        [Select('t'), Update('t', only=True)],
        [Update('t', only=True), Delete('t')],
    ):
        with pytest.raises(PgSafeError, match='the rules for table "t" disagree about `only`') as exc_info:
            Policy(*mismatched)
        assert exc_info.value.kind == 'config'

    with pytest.raises(PgSafeError, match='ONLY cannot be used on the CTE "c"'):
        policy.rewrite('with c as (select id from orders) select id from only c')


def test_only_and_mappers():
    seen: list[Table] = []

    @mapper(Table)
    def record(table: Table, context: Any) -> Table:
        seen.append(table)
        return Table(table.name, alias=table.alias, only=not table.only)

    policy = Policy(Select('family', only=True), Select('orders'), mappers=[record])
    assert policy.rewrite('select f.id, o.id from family f join orders o on o.id = f.id').sql == (
        'SELECT "f"."id", "o"."id" FROM "family" AS "f" INNER JOIN ONLY "orders" AS "o" ON ("o"."id" = "f"."id")'
    )
    assert seen == [Table('family', alias='f', only=True), Table('orders', alias='o')]
    assert seen[0].only
    assert Table('a', only=True) != Table('a')
    assert repr(Table('a', only=True)) == 'Table("a", schema=None, alias=None, only=True)'

    @mapper(Table)
    def only_on_insert(table: Table, context: Any) -> Table:
        return Table(table.name, only=True)

    with pytest.raises(PgSafeError, match='INSERT cannot use ONLY'):
        Policy(Insert('t'), mappers=[only_on_insert]).rewrite('insert into t (a) values (1)')


def test_default_schema():
    policy = Policy(Select('orders', columns=['id']), Delete('public.orders'), default_schema='public')
    safe = policy.rewrite('select * from orders')
    assert safe.sql == 'SELECT "orders"."id" FROM "public"."orders"'
    assert safe.tables == ['public.orders']
    assert policy.rewrite('select id from public.orders').sql == safe.sql
    assert policy.rewrite('delete from orders where id = 1').sql == (
        'DELETE FROM "public"."orders" WHERE ("orders"."id" = 1)'
    )
    with pytest.raises(PgSafeError, match='reading from table "other.orders" is not allowed'):
        policy.rewrite('select id from other.orders')
    with pytest.raises(PgSafeError, match='invalid default schema ""') as exc_info:
        Policy(default_schema='')
    assert exc_info.value.kind == 'config'

    # a mapper is given the qualified table
    seen: list[Table] = []

    @mapper(Table)
    def record(table: Table, context: Any) -> Table:
        seen.append(table)
        return table

    Policy(Select('orders'), default_schema='app', mappers=[record]).rewrite('select id from orders')
    assert seen == [Table('orders', schema='app')]


def test_grants():
    policy = Policy(
        Select('orders', columns=['id', 'qty']),
        Select('app.events'),
        Insert('orders', columns=['qty'], extra=add_tenant),
        Update('orders', columns=['qty']),
        Delete('orders'),
    )
    assert policy.grants('app_role', context={'tenant_id': 1, 'user': 'sam'}) == [
        'GRANT USAGE ON SCHEMA "app" TO "app_role"',
        'GRANT SELECT ("id", "qty") ON "orders" TO "app_role"',
        'GRANT INSERT ("qty", "tenant_id", "created_by") ON "orders" TO "app_role"',
        'GRANT UPDATE ("qty") ON "orders" TO "app_role"',
        'GRANT DELETE ON "orders" TO "app_role"',
        'GRANT SELECT ON "app"."events" TO "app_role"',
    ]
    # `extra` is called to learn its columns, so it needs a context it can work with
    with pytest.raises(PgSafeError) as exc_info:
        policy.grants('app_role')
    assert exc_info.value.kind == 'callback'
    assert isinstance(exc_info.value.__cause__, TypeError)
    with pytest.raises(PgSafeError, match='invalid role ""') as exc_info:
        policy.grants('', context={'tenant_id': 1, 'user': 'sam'})
    assert exc_info.value.kind == 'config'
    assert Policy().grants('r') == []
    assert Policy(Select('t'), default_schema='s').grants('we"ird') == [
        'GRANT USAGE ON SCHEMA "s" TO "we""ird"',
        'GRANT SELECT ON "s"."t" TO "we""ird"',
    ]
