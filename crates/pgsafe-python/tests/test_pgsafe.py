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
    safe = policy.check('select id from orders where qty < 3')
    assert safe.sql == 'SELECT "orders"."id" FROM "orders" WHERE ("orders"."qty" < 3)'
    assert safe.params == []
    assert safe.kind == 'select'
    assert safe.tables == ['orders']
    assert repr(safe) == (
        'SafeSql(sql="SELECT \\"orders\\".\\"id\\" FROM \\"orders\\" WHERE (\\"orders\\".\\"qty\\" < 3)", '
        'params=[], kind="select", tables=["orders"])'
    )


def test_star_is_expanded(policy: Policy):
    assert policy.check('select * from orders').sql == (
        'SELECT "orders"."id", "orders"."product", "orders"."qty" FROM "orders"'
    )
    assert policy.check('select * from v').sql == 'SELECT "v".* FROM "v"'


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
        policy.check(sql)
    error = exc_info.value
    assert error.kind == kind
    assert error.message == message
    assert isinstance(error, ValueError)
    assert kind in pgsafe.ERROR_KINDS


def test_error_position(policy: Policy):
    with pytest.raises(PgSafeError) as exc_info:
        policy.check("select id,\n  U&'x'\nfrom orders")
    error = exc_info.value
    assert str(error) == 'this kind of literal is not supported at line 2, column 3'
    assert error.message == 'this kind of literal is not supported'
    assert (error.line, error.column) == (2, 3)

    with pytest.raises(PgSafeError) as exc_info:
        policy.check('select secret from orders')
    assert (exc_info.value.line, exc_info.value.column) == (None, None)


def test_injection_stays_a_literal(policy: Policy):
    sql = r"select id from orders where product = 'x\'' UNION SELECT password FROM users --'"
    assert policy.check(sql).sql == (
        r"""SELECT "orders"."id" FROM "orders" WHERE ("orders"."product" = E'x\\'' UNION SELECT password FROM users --')"""
    )


def test_insert_extra_callable(policy: Policy):
    safe = policy.check("insert into orders (product, qty) values ('tea', 2)", context={'tenant_id': 42, 'user': 'sam'})
    assert safe.sql == (
        'INSERT INTO "orders" ("product", "qty", "tenant_id", "created_by") VALUES (\'tea\', 2, 42, \'sam\')'
    )
    assert safe.kind == 'insert'
    assert safe.tables == ['orders']


def test_insert_extra_dict_and_values():
    policy = Policy(
        Insert(
            't', extra={'a': None, 'b': True, 'c': -5, 'd': 1.5, 'e': "it's", 'f': 10**30, 'g': float('inf'), 'h': -0.0}
        )
    )
    assert policy.check('insert into t (x) values (1), (2)').sql == (
        'INSERT INTO "t" ("x", "a", "b", "c", "d", "e", "f", "g", "h") VALUES '
        "(1, NULL, TRUE, (- 5), 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0), "
        "(2, NULL, TRUE, (- 5), 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0)"
    )


def test_insert_extra_collision(policy: Policy):
    context = {'tenant_id': 42, 'user': 'sam'}
    # the rule lists the columns a statement may set, and `tenant_id` is not one of them
    with pytest.raises(PgSafeError, match='inserting into these columns of table "orders" is not allowed: tenant_id'):
        policy.check("insert into orders (product, tenant_id) values ('tea', 1)", context=context)

    # a rule that allows any column still refuses the ones the policy sets
    open_policy = Policy(Insert('orders', extra=add_tenant))
    with pytest.raises(PgSafeError, match='is set by the policy and cannot be set by the statement') as exc_info:
        open_policy.check("insert into orders (product, tenant_id) values ('tea', 1)", context=context)
    assert exc_info.value.kind == 'denied'


def test_insert_extra_raises(policy: Policy):
    with pytest.raises(PgSafeError) as exc_info:
        policy.check("insert into orders (product, qty) values ('tea', 2)", context={})
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
        policy.check('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'
    assert isinstance(exc_info.value.__cause__, TypeError)


def test_insert_extra_bad_column():
    policy = Policy(Insert('t', extra={'': 1}))
    with pytest.raises(PgSafeError, match='extra returned an invalid column') as exc_info:
        policy.check('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'

    with pytest.raises(TypeError, match='extra must be a dict or a callable returning a dict'):
        Insert('t', extra=[('a', 1)])  # pyright: ignore[reportArgumentType]


def test_update_and_delete(policy: Policy):
    safe = policy.check('update orders set qty = qty + 1 where id = 5 returning *')
    assert safe.sql == (
        'UPDATE "orders" SET "qty" = ("orders"."qty" + 1) WHERE ("orders"."id" = 5) '
        'RETURNING "orders"."id", "orders"."product", "orders"."qty"'
    )
    assert safe.kind == 'update'
    safe = policy.check('delete from orders where id = 1')
    assert safe.sql == 'DELETE FROM "orders" WHERE ("orders"."id" = 1)'
    assert safe.kind == 'delete'

    unfiltered = Policy(Update('orders', allow_unfiltered=True), Delete('orders', allow_unfiltered=True))
    assert unfiltered.check('update orders set qty = 1').sql == 'UPDATE "orders" SET "qty" = 1'
    assert unfiltered.check('delete from orders').sql == 'DELETE FROM "orders"'


def test_allow(policy: Policy):
    assert policy.check('select id from orders', allow=['select']).kind == 'select'
    with pytest.raises(PgSafeError, match='DELETE statements are not allowed here'):
        policy.check('delete from orders where id = 1', allow=['select', 'insert'])
    with pytest.raises(PgSafeError, match='unknown statement kind "merge"') as exc_info:
        policy.check('select 1', allow=['merge'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'


def test_functions():
    policy = Policy(Select('orders'), functions=['app.order_total'], deny_functions=['random', 'now'])
    assert policy.check('select app.order_total(id), lower(product) from orders').sql == (
        'SELECT "app"."order_total"("orders"."id"), pg_catalog."lower"("orders"."product") FROM "orders"'
    )
    for sql in 'select random()', 'select now()', 'select order_total(1)':
        with pytest.raises(PgSafeError, match='is not allowed'):
            policy.check(sql)

    with pytest.raises(PgSafeError, match='cannot deny function "pg_sleep": it is not an allowed function'):
        Policy(deny_functions=['pg_sleep'])

    bare = Policy(Select('orders'), default_functions=False)
    with pytest.raises(PgSafeError, match='function "count" is not allowed'):
        bare.check('select count(*) from orders')

    assert 'count' in pgsafe.DEFAULT_FUNCTIONS
    assert 'pg_sleep' not in pgsafe.DEFAULT_FUNCTIONS
    assert isinstance(pgsafe.DEFAULT_FUNCTIONS, frozenset)


def test_operators():
    policy = Policy(Select('orders', operators=['=', 'and']), Select('other'), operators=['<', '~'])
    assert policy.check('select id from orders where id = 1 and qty = 2').kind == 'select'
    with pytest.raises(PgSafeError, match='operator not allowed on table "orders": <'):
        policy.check('select id from orders where id < 1')
    assert policy.check("select id from other where id < 1 and name ~ 'x'".replace(' and ', ' < ')).kind == 'select'

    with pytest.raises(PgSafeError, match='unknown operator "xor"') as exc_info:
        Select('orders', operators=['xor'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'
    with pytest.raises(PgSafeError, match='unknown operator "xor"'):
        Policy(operators=['xor'])  # pyright: ignore[reportArgumentType]


def test_star_behaviour():
    with pytest.raises(PgSafeError, match=r'\* is not allowed, list the columns'):
        Policy(Select('v'), star_behaviour='reject').check('select * from v')
    allow = Policy(Select('v'), Select('orders', columns=['id']), star_behaviour='allow')
    assert allow.check('select * from v').sql == 'SELECT * FROM "v"'
    with pytest.raises(PgSafeError, match='only some of its columns are allowed'):
        allow.check('select * from orders')
    with pytest.raises(PgSafeError, match='unknown star behaviour "maybe"'):
        Policy(star_behaviour='maybe')  # pyright: ignore[reportArgumentType]


def test_params():
    policy = Policy(Select('orders'), literals='params')
    safe = policy.check("select id from orders where product = 'tea' and qty = $1 and note = 'it''s'")
    assert safe.sql == (
        'SELECT "orders"."id" FROM "orders" '
        'WHERE ((("orders"."product" = $2) AND ("orders"."qty" = $1)) AND ("orders"."note" = $3))'
    )
    assert safe.params == ['tea', "it's"]
    with pytest.raises(PgSafeError, match='unknown literals mode "bind"'):
        Policy(literals='bind')  # pyright: ignore[reportArgumentType]


def test_max_rows_dialect_limits():
    policy = Policy(Select('orders'), max_rows=10)
    assert policy.check('select id from orders').sql == 'SELECT "orders"."id" FROM "orders" LIMIT 10'
    assert policy.check('select id from orders limit 3').sql == 'SELECT "orders"."id" FROM "orders" LIMIT 3'

    mysql = Policy(Select('orders'), dialect='mysql')
    assert mysql.check('select `id` from `orders`').sql == 'SELECT "orders"."id" FROM "orders"'
    with pytest.raises(PgSafeError, match='unknown dialect "oracle"'):
        Policy(dialect='oracle')  # pyright: ignore[reportArgumentType]

    limits = Limits(max_sql_bytes=30, max_joins=0)
    assert limits.max_sql_bytes == 30
    assert limits.max_joins == 0
    assert limits.max_depth == 50
    assert repr(limits).startswith('Limits(max_sql_bytes=30, max_depth=50, ')
    tight = Policy(Select('orders'), limits=limits)
    with pytest.raises(PgSafeError, match='SQL is 38 bytes, the limit is 30') as exc_info:
        tight.check('select id from orders where qty > 1000')
    assert exc_info.value.kind == 'limit'
    with pytest.raises(PgSafeError, match='max_depth must be at least 1'):
        Policy(limits=Limits(max_depth=0))


def test_rules():
    select = Select('orders', columns=('id', 'qty'), operators=['='])
    assert (select.table, select.columns, select.operators) == ('orders', ['id', 'qty'], ['='])
    assert repr(select) == 'Select("orders", columns=["id", "qty"], operators=["="])'
    assert repr(Select('v')) == 'Select("v", columns=None, operators=None)'
    insert = Insert('orders', columns=['id'])
    assert (insert.table, insert.columns) == ('orders', ['id'])
    assert repr(insert) == 'Insert("orders", columns=["id"])'
    update = Update('orders', columns=['qty'], allow_unfiltered=True)
    assert (update.table, update.columns, update.allow_unfiltered) == ('orders', ['qty'], True)
    assert repr(update) == 'Update("orders", columns=["qty"], allow_unfiltered=True)'
    delete = Delete('orders')
    assert (delete.table, delete.allow_unfiltered) == ('orders', False)
    assert repr(delete) == 'Delete("orders", allow_unfiltered=False)'

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
    safe = policy.check('select e.id, other.x from events e join other on other.id = e.id', context=42)
    assert safe.sql == (
        'SELECT "e"."id", "other"."x" FROM "tenants"."events_42" AS "e" INNER JOIN "other" ON ("other"."id" = "e"."id")'
    )
    # the tables are reported as the statement named them
    assert safe.tables == ['events', 'other']
    assert seen == [(Table('events', alias='e'), 42), (Table('other'), 42)]

    # without an alias, the original name is kept as one so that the columns still resolve
    assert policy.check('select id from events', context=7).sql == (
        'SELECT "events"."id" FROM "tenants"."events_7" AS "events"'
    )
    assert policy.check('insert into events (a) values (1) returning a', context=7).sql == (
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
    assert policy.check("select created, lower(a || 'x') from v where b = 'secret' and c < now()").sql == (
        'SELECT pg_catalog."date_trunc"(\'day\', "v"."created"), pg_catalog."upper"(("v"."a" || \'x\')) '
        'FROM "v" WHERE (("v"."b" = NULL) AND ("v"."c" < "app"."frozen_now"()))'
    )

    # modifiers survive `replace`
    @mapper(Function)
    def rename_count(function: Function, context: Any) -> pgsafe.ExprLike:
        return function.replace(name='my_count', schema=None) if function.name == 'count' else function

    policy = Policy(Select('v'), mappers=[rename_count])
    assert policy.check('select count(distinct a) filter (where b > 1) over (partition by c) from v').sql == (
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
            policy.check(sql)
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
    assert repr(table) == 'Table("orders", schema="app", alias="o")'
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

    for value in None, True, False, 0, 42, 1.5, 'text', '':
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
    assert policy.check("select a from v where b = 'x'").sql == (
        'SELECT "v"."a" FROM "a""b"."x""; DROP TABLE orders; --" AS "v" '
        """WHERE ("v"."b" = E'''; DROP TABLE orders; --\\\\')"""
    )


def test_version():
    assert isinstance(pgsafe.__version__, str)
    assert pgsafe.__version__.count('.') == 2
