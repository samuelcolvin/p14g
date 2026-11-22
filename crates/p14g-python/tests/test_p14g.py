from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import Any, LiteralString, assert_type, get_args, get_origin

import p14g
import pytest
from p14g import Delete, Insert, Limits, P14gError, Policy, Select, Update

# every statement on one line, which is easier to compare against
DensePolicy = partial(Policy, layout='dense')


def add_tenant(context: dict[str, Any]) -> dict[str, Any]:
    return {'tenant_id': context['tenant_id'], 'created_by': context['user']}


@pytest.fixture(name='policy')
def fixture_policy() -> Policy:
    return DensePolicy(
        Select('orders', columns=['id', 'product', 'qty']),
        Select('v', ['id', 'name']),
        Insert('orders', columns=['product', 'qty'], extra=add_tenant),
        Update('orders', columns=['qty']),
        Delete('orders'),
    )


def test_select(policy: Policy):
    safe = policy.rewrite('select id from orders where qty < 3')
    assert safe.sql == 'SELECT orders.id FROM orders WHERE orders.qty < 3'
    assert safe.params == []
    assert safe.kind == 'select'
    assert safe.tables == ['orders']
    assert repr(safe) == (
        'SafeSql(sql="SELECT orders.id FROM orders WHERE orders.qty < 3", params=[], kind="select", tables=["orders"])'
    )


def test_star_is_expanded(policy: Policy):
    assert policy.rewrite('select * from orders').sql == ('SELECT orders.id, orders.product, orders.qty FROM orders')
    assert policy.rewrite('select * from v').sql == 'SELECT v.id, v.name FROM v'


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
        ("select id from orders where product ~ 'x'", 'denied', 'operator not allowed: ~'),
    ],
)
def test_rejected(policy: Policy, sql: str, kind: str, message: str):
    with pytest.raises(P14gError) as exc_info:
        policy.rewrite(sql)
    error = exc_info.value
    assert error.kind == kind
    assert error.message == message
    assert isinstance(error, ValueError)
    assert kind in p14g.ERROR_KINDS


def test_error_position(policy: Policy):
    with pytest.raises(P14gError) as exc_info:
        policy.rewrite("select id,\n  U&'x'\nfrom orders")
    error = exc_info.value
    assert str(error) == 'this kind of literal is not supported at line 2, column 3'
    assert error.message == 'this kind of literal is not supported'
    assert (error.line, error.column) == (2, 3)

    with pytest.raises(P14gError) as exc_info:
        policy.rewrite('select secret from orders')
    assert (exc_info.value.line, exc_info.value.column) == (None, None)


def test_injection_stays_a_literal(policy: Policy):
    sql = r"select id from orders where product = 'x\'' UNION SELECT password FROM users --'"
    assert policy.rewrite(sql).sql == (
        "SELECT orders.id FROM orders WHERE orders.product = E'x\\\\'' UNION SELECT password FROM users --'"
    )


def test_insert_extra_callable(policy: Policy):
    safe = policy.rewrite(
        "insert into orders (product, qty) values ('tea', 2)", context={'tenant_id': 42, 'user': 'sam'}
    )
    assert safe.sql == ("INSERT INTO orders (product, qty, tenant_id, created_by) VALUES ('tea', 2, 42, 'sam')")
    assert safe.kind == 'insert'
    assert safe.tables == ['orders']


def test_insert_extra_dict_and_values():
    policy = DensePolicy(
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
        "INSERT INTO t (x, a, b, c, d, e, f, g, h, i) VALUES (1, NULL, TRUE, - 5, 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0.0, 2.0), (2, NULL, TRUE, - 5, 1.5, 'it''s', 1000000000000000000000000000000, CAST('Infinity' AS double precision), 0.0, 2.0)"
    )


def test_insert_extra_collision(policy: Policy):
    context = {'tenant_id': 42, 'user': 'sam'}
    # the rule lists the columns a statement may set, and `tenant_id` is not one of them
    with pytest.raises(P14gError, match='inserting into these columns of table "orders" is not allowed: tenant_id'):
        policy.rewrite("insert into orders (product, tenant_id) values ('tea', 1)", context=context)

    # a rule that allows any column still refuses the ones the policy sets
    open_policy = DensePolicy(Insert('orders', extra=add_tenant))
    with pytest.raises(P14gError, match='is set by the policy and cannot be set by the statement') as exc_info:
        open_policy.rewrite("insert into orders (product, tenant_id) values ('tea', 1)", context=context)
    assert exc_info.value.kind == 'denied'


def test_insert_extra_raises(policy: Policy):
    with pytest.raises(P14gError) as exc_info:
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
    policy = DensePolicy(Insert('t', extra=extra))
    with pytest.raises(P14gError) as exc_info:
        policy.rewrite('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'
    assert isinstance(exc_info.value.__cause__, TypeError)


def test_insert_extra_bad_column():
    policy = DensePolicy(Insert('t', extra={'': 1}))
    with pytest.raises(P14gError, match='extra returned an invalid column') as exc_info:
        policy.rewrite('insert into t (x) values (1)')
    assert exc_info.value.kind == 'callback'

    with pytest.raises(TypeError, match='extra must be a dict or a callable returning a dict'):
        Insert('t', extra=[('a', 1)])  # pyright: ignore[reportArgumentType]


def test_update_and_delete(policy: Policy):
    safe = policy.rewrite('update orders set qty = qty + 1 where id = 5 returning *')
    assert safe.sql == (
        'UPDATE orders SET qty = orders.qty + 1 WHERE orders.id = 5 RETURNING orders.id, orders.product, orders.qty'
    )
    assert safe.kind == 'update'
    safe = policy.rewrite('delete from orders where id = 1')
    assert safe.sql == 'DELETE FROM orders WHERE orders.id = 1'
    assert safe.kind == 'delete'

    unfiltered = DensePolicy(Update('orders', allow_unfiltered=True), Delete('orders', allow_unfiltered=True))
    assert unfiltered.rewrite('update orders set qty = 1').sql == 'UPDATE orders SET qty = 1'
    assert unfiltered.rewrite('delete from orders').sql == 'DELETE FROM orders'


def test_allow(policy: Policy):
    assert policy.rewrite('select id from orders', allow=['select']).kind == 'select'
    with pytest.raises(P14gError, match='DELETE statements are not allowed here'):
        policy.rewrite('delete from orders where id = 1', allow=['select', 'insert'])
    with pytest.raises(P14gError, match='unknown statement kind "merge"') as exc_info:
        policy.rewrite('select 1', allow=['merge'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'


def test_functions():
    policy = DensePolicy(
        Select('orders', ['id', 'product']), functions=['app.order_total'], deny_functions=['random', 'now']
    )
    assert policy.rewrite('select app.order_total(id), lower(product) from orders').sql == (
        'SELECT app.order_total(orders.id), lower(orders.product) FROM orders'
    )
    for sql in 'select random()', 'select now()', 'select order_total(1)':
        with pytest.raises(P14gError, match='is not allowed'):
            policy.rewrite(sql)

    with pytest.raises(P14gError, match='cannot deny function "pg_sleep": it is not an allowed function'):
        DensePolicy(deny_functions=['pg_sleep'])

    bare = DensePolicy(Select('orders', ['id']), default_functions=False)
    with pytest.raises(P14gError, match='function "count" is not allowed'):
        bare.rewrite('select count(*) from orders')


def test_role_cannot_change():
    policy = DensePolicy(Select('orders', ['id']))
    for sql in (
        'set role postgres',
        'reset role',
        'commit',
        "select set_config('role', 'none', false)",
        # Postgres would read `orders.reset_role` as the call `reset_role(orders)`
        'select reset_role from orders',
        'select o.row_to_json from orders o',
    ):
        with pytest.raises(P14gError):
            policy.rewrite(sql)

    with pytest.raises(TypeError):
        Select('orders')  # pyright: ignore[reportCallIssue]
    with pytest.raises(P14gError, match='the select rule for table "orders" lists no columns') as exc_info:
        DensePolicy(Select('orders', []))
    assert exc_info.value.kind == 'config'
    with pytest.raises(P14gError) as exc_info:
        DensePolicy(Select('orders', ['id', '*']))
    assert exc_info.value.message == (
        'the select rule for table "orders" lists "*": for security reasons a select rule must list each column it '
        'allows by name, see "Why every column is listed" in the README'
    )
    assert exc_info.value.kind == 'config'
    with pytest.raises(P14gError, match='leave out `columns` to allow every column'):
        DensePolicy(Update('orders', columns=['*']))

    assert 'count' in p14g.DEFAULT_FUNCTIONS
    assert 'pg_sleep' not in p14g.DEFAULT_FUNCTIONS
    assert isinstance(p14g.DEFAULT_FUNCTIONS, frozenset)


def test_operators():
    policy = DensePolicy(Select('orders', ['id', 'qty', 'product']), operators=['=', 'and'])
    assert policy.rewrite('select id from orders where id = 1 and qty = 2').kind == 'select'
    with pytest.raises(P14gError, match='operator not allowed: <'):
        policy.rewrite('select id from orders where id < 1')
    # the same list applies to a column that comes through a subquery, and to no column at all
    with pytest.raises(P14gError, match='operator not allowed: <'):
        policy.rewrite('select x from (select id as x from orders) d where x < 1')
    with pytest.raises(P14gError, match='operator not allowed: <'):
        policy.rewrite('select 1 < 2')

    with pytest.raises(P14gError, match='operator not allowed: ~'):
        DensePolicy(Select('orders', ['id', 'product'])).rewrite("select id from orders where product ~ 'x'")
    regex = DensePolicy(Select('orders', ['id', 'product']), operators=['~'])
    assert regex.rewrite("select id from orders where product ~ 'x'").kind == 'select'

    with pytest.raises(P14gError, match='unknown operator "xor"') as exc_info:
        DensePolicy(operators=['xor'])  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'
    with pytest.raises(TypeError, match='operators'):
        Select('orders', ['id'], operators=['='])  # pyright: ignore[reportCallIssue]


def test_star_behaviour():
    with pytest.raises(P14gError, match=r'\* is not allowed, list the columns'):
        DensePolicy(Select('v', ['id']), star_behaviour='reject').rewrite('select * from v')
    for behaviour in 'maybe', 'allow':
        with pytest.raises(P14gError, match=f'unknown star behaviour "{behaviour}"'):
            DensePolicy(star_behaviour=behaviour)  # pyright: ignore[reportArgumentType]


def test_params():
    policy = DensePolicy(Select('orders', ['id', 'product', 'qty', 'note']), literals='params')
    safe = policy.rewrite("select id from orders where product = 'tea' and qty = $1 and note = 'it''s'")
    assert safe.sql == (
        'SELECT orders.id FROM orders WHERE orders.product = $2 AND orders.qty = $1 AND orders.note = $3'
    )
    assert safe.params == ['tea', "it's"]
    with pytest.raises(P14gError, match='unknown literals mode "bind"'):
        DensePolicy(literals='bind')  # pyright: ignore[reportArgumentType]


def test_max_rows_dialect_limits():
    policy = DensePolicy(Select('orders', ['id']), max_rows=10)
    assert policy.rewrite('select id from orders').sql == 'SELECT orders.id FROM orders LIMIT 10'
    assert policy.rewrite('select id from orders limit 3').sql == 'SELECT orders.id FROM orders LIMIT 3'

    mysql = DensePolicy(Select('orders', ['id']), dialect='mysql')
    assert mysql.rewrite('select `id` from `orders`').sql == 'SELECT orders.id FROM orders'
    with pytest.raises(P14gError, match='unknown dialect "oracle"'):
        DensePolicy(dialect='oracle')  # pyright: ignore[reportArgumentType]

    limits = Limits(max_sql_bytes=30, max_joins=0)
    assert limits.max_sql_bytes == 30
    assert limits.max_joins == 0
    assert limits.max_depth == 50
    assert repr(limits).startswith('Limits(max_sql_bytes=30, max_depth=50, ')
    tight = DensePolicy(Select('orders', ['id', 'qty']), limits=limits)
    with pytest.raises(P14gError, match='SQL is 38 bytes, the limit is 30') as exc_info:
        tight.rewrite('select id from orders where qty > 1000')
    assert exc_info.value.kind == 'limit'
    with pytest.raises(P14gError, match='max_depth must be at least 1'):
        DensePolicy(limits=Limits(max_depth=0))


def test_rules():
    select = Select('orders', columns=('id', 'qty'))
    assert (select.table, select.columns) == ('orders', ['id', 'qty'])
    assert repr(select) == 'Select("orders", columns=["id", "qty"], only=False)'
    assert repr(Select('v', ['a'])) == 'Select("v", columns=["a"], only=False)'
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
        DensePolicy('orders')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        Select('orders', columns='id')
    with pytest.raises(P14gError, match='invalid table name "a.b.c"') as exc_info:
        DensePolicy(Select('a.b.c', ['a']))
    assert exc_info.value.kind == 'config'


def test_version():
    assert isinstance(p14g.__version__, str)
    assert p14g.__version__.count('.') == 2


def test_rules_cannot_be_pickled():
    import copy
    import pickle

    for value in Select('a', ['b']), DensePolicy():
        with pytest.raises(TypeError, match='cannot pickle'):
            pickle.dumps(value)
        with pytest.raises(TypeError, match='cannot pickle'):
            copy.deepcopy(value)


def test_rules_are_immutable():
    for value, attribute in (Select('a', ['b']), 'table'), (Limits(), 'max_depth'):
        with pytest.raises(AttributeError):
            setattr(value, attribute, 'x')
    safe = DensePolicy().rewrite('select 1')
    with pytest.raises(AttributeError):
        safe.sql = 'drop table x'  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(TypeError, match='cannot create'):
        p14g.SafeSql()  # pyright: ignore[reportCallIssue]


def test_context_is_passed_through_unchanged():
    marker = object()
    seen: list[Any] = []

    def filter(context: Any) -> LiteralString:
        seen.append(context)
        return 'true'

    def extra(context: Any) -> dict[str, Any]:
        seen.append(context)
        return {}

    policy = DensePolicy(Select('t', ['a'], filter=filter), Insert('t', extra=extra))
    policy.rewrite('insert into t (a) values (1)', context=marker)
    assert seen == [marker]
    seen.clear()
    policy.rewrite('select a from t', context=marker)
    assert seen == [marker]
    seen.clear()
    policy.rewrite('select a from t')
    assert seen == [None]


def test_extra_is_called_once_per_check():
    calls = 0

    def extra(context: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {'n': calls}

    policy = DensePolicy(Insert('t', extra=extra))
    assert policy.rewrite('insert into t (a) values (1), (2), (3)').sql == (
        'INSERT INTO t (a, n) VALUES (1, 1), (2, 1), (3, 1)'
    )
    assert calls == 1
    # not called for a statement that is rejected before the rule is reached
    with pytest.raises(P14gError):
        policy.rewrite('insert into other (a) values (1)')
    assert calls == 1


def test_extra_values():
    policy = DensePolicy(Insert('t', extra={'s': 's', 'null': None, 'b': True, 'neg': -1.5, 'nan': float('nan')}))
    assert policy.rewrite('insert into t (a) values (1)').sql == (
        "INSERT INTO t (a, s, \"null\", b, neg, nan) VALUES (1, 's', NULL, TRUE, - 1.5, CAST('NaN' AS double precision))"
    )
    params = DensePolicy(Insert('t', extra={'s': 'from policy'}), literals='params')
    safe = params.rewrite("insert into t (a) values ('x')")
    assert safe.sql == 'INSERT INTO t (a, s) VALUES ($1, $2)'
    assert safe.params == ['x', 'from policy']
    with pytest.raises(TypeError, match='expected None, bool, int, float or str, not bytes'):
        Insert('t', extra={'a': b'bytes'})  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError, match='the keys of extra must be column names'):
        Insert('t', extra={1: 'a'})  # pyright: ignore[reportArgumentType]


def test_policy_can_be_used_from_a_callback():
    inner = DensePolicy(Select('v', ['a']))

    def nested(context: Any) -> dict[str, Any]:
        return {'b': inner.rewrite('select a from v').sql}

    outer = DensePolicy(Insert('v', extra=nested))
    assert outer.rewrite('insert into v (a) values (1)').sql == ("INSERT INTO v (a, b) VALUES (1, 'SELECT v.a FROM v')")

    # and a policy can check from inside its own callback
    policies: list[Policy] = []

    def recursive(context: int) -> dict[str, Any]:
        if context == 0:
            return {}
        return {'b': policies[0].rewrite('insert into v (a) values (1)', context=context - 1).sql}

    policies.append(DensePolicy(Insert('v', extra=recursive)))
    assert policies[0].rewrite('insert into v (a) values (1)', context=2).sql == (
        "INSERT INTO v (a, b) VALUES (1, 'INSERT INTO v (a, b) VALUES (1, ''INSERT INTO v (a) VALUES (1)'')')"
    )


def test_threads():
    from concurrent.futures import ThreadPoolExecutor

    def extra(context: int) -> dict[str, int]:
        return {'n': context}

    def by_n(context: int) -> tuple[LiteralString, dict[str, int]]:
        return 'n = :n', {'n': context}

    policy = DensePolicy(Select('t', columns=['a'], filter=by_n), Insert('t', extra=extra))

    def work(n: int) -> list[str]:
        out: list[str] = []
        for _ in range(200):
            out.append(policy.rewrite('select * from t where a = 1', context=n).sql)
            out.append(policy.rewrite('insert into t (a) values (1)', context=n).sql)
            with pytest.raises(P14gError):
                policy.rewrite('select b from t', context=n)
        return out

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(work, range(16)))
    for n, result in enumerate(results):
        assert set(result) == {
            f'SELECT t.a FROM (SELECT t.a FROM t WHERE t.n = {n}) AS t WHERE t.a = 1',
            f'INSERT INTO t (a, n) VALUES (1, {n})',
        }


def test_check_arguments():
    policy = DensePolicy(Select('v', ['a']))
    with pytest.raises(TypeError):
        policy.rewrite(b'select 1')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        policy.rewrite('select 1', 'context')  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError):
        policy.rewrite('select 1', allow='select')  # pyright: ignore[reportArgumentType]
    with pytest.raises(P14gError, match='SELECT statements are not allowed here'):
        policy.rewrite('select 1', allow=[])
    assert policy.rewrite('SELECT 1', allow=['SELECT', 'Insert']).kind == 'select'  # pyright: ignore[reportArgumentType]
    # the input is unicode, not bytes: a lone surrogate cannot be encoded
    with pytest.raises(UnicodeEncodeError):
        policy.rewrite("select '\ud800'")
    assert policy.rewrite("select 'café \U0001f600'").sql == "SELECT 'café \U0001f600'"
    with pytest.raises(P14gError, match='string literals may not contain NUL'):
        policy.rewrite("select 'a\0b'")


def test_policy_arguments():
    with pytest.raises(TypeError):
        DensePolicy(functions='count')  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        DensePolicy(limits={'max_depth': 1})  # pyright: ignore[reportArgumentType]
    with pytest.raises(TypeError):
        DensePolicy(Select('v', ['a']), Select)  # pyright: ignore[reportArgumentType]
    with pytest.raises((TypeError, OverflowError)):
        DensePolicy(max_rows=-1)
    with pytest.raises((TypeError, OverflowError)):
        Limits(max_depth=-1)
    # an empty policy allows statements that touch no table
    empty = DensePolicy()
    assert empty.rewrite('select 1 + 1, lower($1)').sql == 'SELECT 1 + 1, lower($1)'
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
        policy = DensePolicy(Select('v', ['a', 'b', 'c']), Insert('v'), limits=Limits(**limits))
        with pytest.raises(P14gError) as exc_info:
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


def test_value_alias():
    import typing

    assert set(typing.get_args(p14g.Value)) == {type(None), bool, int, float, str}
    public = {name for name in dir(p14g) if not name.startswith('_') and name != 'p14g'}
    assert set(p14g.__all__) == public | {'__version__'}


def test_error_is_a_normal_exception():
    error = P14gError('message')
    assert str(error) == 'message'
    assert not hasattr(error, 'kind')
    try:
        DensePolicy().rewrite('select * from t')
    except ValueError as e:
        assert isinstance(e, P14gError)
        assert e.args == ('reading from table "t" is not allowed',)
        assert e.__cause__ is None


def test_only():
    policy = DensePolicy(
        Select('family', columns=['id'], only=True),
        Update('family', only=True),
        Delete('family', only=True),
        Insert('family'),
        Select('orders', ['id']),
        Update('orders'),
    )
    assert policy.rewrite('select * from family f where id = 1').sql == (
        'SELECT f.id FROM ONLY "family" AS f WHERE f.id = 1'
    )
    assert policy.rewrite('update family set name = 1 where id = 1').sql == (
        'UPDATE ONLY "family" SET "name" = 1 WHERE "family".id = 1'
    )
    assert policy.rewrite('delete from family where id = 1').sql == 'DELETE FROM ONLY "family" WHERE "family".id = 1'
    # INSERT has no ONLY: a row goes into the table it names
    assert policy.rewrite('insert into family (id) values (1) returning id').sql == (
        'INSERT INTO "family" (id) VALUES (1) RETURNING "family".id'
    )
    # a statement can ask for ONLY on any table, and its absence on a table the policy marks changes nothing
    assert policy.rewrite('select id from only orders').sql == 'SELECT orders.id FROM ONLY orders'
    assert policy.rewrite('update only orders set qty = 1 where id = 1').sql == (
        'UPDATE ONLY orders SET qty = 1 WHERE orders.id = 1'
    )
    assert policy.rewrite('select id from orders').sql == 'SELECT orders.id FROM orders'
    assert policy.rewrite('select id from only family').sql == 'SELECT "family".id FROM ONLY "family"'

    rules = Select('t', ['a'], only=True), Update('t', only=True), Delete('t', only=True)
    assert [rule.only for rule in rules] == [True, True, True]
    assert repr(rules[2]) == 'Delete("t", allow_unfiltered=False, only=True)'
    assert not Select('t', ['a']).only

    for mismatched in (
        [Select('t', ['a'], only=True), Select('t', ['a'])],
        [Select('t', ['a']), Update('t', only=True)],
        [Update('t', only=True), Delete('t')],
    ):
        with pytest.raises(P14gError, match='the rules for table "t" disagree about `only`') as exc_info:
            DensePolicy(*mismatched)
        assert exc_info.value.kind == 'config'

    with pytest.raises(P14gError, match='ONLY cannot be used on the CTE "c"'):
        policy.rewrite('with c as (select id from orders) select id from only c')


def test_default_schema():
    policy = DensePolicy(Select('orders', columns=['id']), Delete('public.orders'), default_schema='public')
    safe = policy.rewrite('select * from orders')
    assert safe.sql == 'SELECT orders.id FROM public.orders'
    assert safe.tables == ['public.orders']
    assert policy.rewrite('select id from public.orders').sql == safe.sql
    assert policy.rewrite('delete from orders where id = 1').sql == ('DELETE FROM public.orders WHERE orders.id = 1')
    with pytest.raises(P14gError, match='reading from table "other.orders" is not allowed'):
        policy.rewrite('select id from other.orders')
    with pytest.raises(P14gError, match='invalid default schema ""') as exc_info:
        DensePolicy(default_schema='')
    assert exc_info.value.kind == 'config'


def test_grants():
    policy = DensePolicy(
        Select('orders', columns=['id', 'qty']),
        Select('app.events', ['id', 'kind']),
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
        'GRANT SELECT ("id", "kind") ON "app"."events" TO "app_role"',
    ]
    # `extra` is called to learn its columns, so it needs a context it can work with
    with pytest.raises(P14gError) as exc_info:
        policy.grants('app_role')
    assert exc_info.value.kind == 'callback'
    assert isinstance(exc_info.value.__cause__, TypeError)
    with pytest.raises(P14gError, match='invalid role ""') as exc_info:
        policy.grants('', context={'tenant_id': 1, 'user': 'sam'})
    assert exc_info.value.kind == 'config'
    assert DensePolicy().grants('r') == []
    assert DensePolicy(Select('t', ['a']), default_schema='s').grants('we"ird') == [
        'GRANT USAGE ON SCHEMA "s" TO "we""ird"',
        'GRANT SELECT ("a") ON "s"."t" TO "we""ird"',
    ]


def test_quote_identifiers():
    columns = ['id', 'user', 'Mixed', 'with space', 'name', 'a']
    minimal = Policy(Select('orders', columns), layout='dense')
    always = Policy(Select('orders', columns), layout='dense', quote_identifiers='always')
    sql = 'select id, "user", "Mixed", "with space", name as "select", 1 as plain from orders o where "user" = 1'
    # only what needs quoting: anything not plain lower case, and keywords where they are not after a dot
    assert minimal.rewrite(sql).sql == (
        'SELECT o.id, o.user, o."Mixed", o."with space", o.name AS "select", 1 AS plain FROM orders AS o WHERE o.user = 1'
    )
    assert always.rewrite(sql).sql == (
        'SELECT "o"."id", "o"."user", "o"."Mixed", "o"."with space", "o"."name" AS "select", 1 AS "plain" '
        'FROM "orders" AS "o" WHERE "o"."user" = 1'
    )
    # a table called `user` must be quoted, or Postgres reads the current role
    users = Policy(Select('user', ['id']), layout='dense')
    assert users.rewrite('select id from "user"').sql == 'SELECT "user".id FROM "user"'
    assert minimal.rewrite('select lower(a), left(a, 1) from orders').sql == (
        'SELECT lower(orders.a), left(orders.a, 1) FROM orders'
    )
    with pytest.raises(P14gError, match='unknown quote_identifiers "never"') as exc_info:
        Policy(quote_identifiers='never')  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'
    # grants are always quoted
    assert minimal.grants('app') == [
        'GRANT SELECT ("id", "user", "Mixed", "with space", "name", "a") ON "orders" TO "app"'
    ]


def test_layout():
    policy = Policy(
        Select('orders', ['id', 'qty', 'cid', 'a', 'b']),
        Select('customers', ['id', 'name']),
        Insert('orders'),
        Update('orders'),
        Delete('orders'),
    )
    assert policy.rewrite(
        'with big as (select id from orders where qty > 1) '
        'select o.id, c.name, count(*) from orders o join customers c on c.id = o.cid left join big on big.id = o.id '
        'where o.qty > 1 and o.id in (select id from big) group by o.id, c.name having count(*) > 1 '
        'order by o.id desc limit 10 offset 5'
    ).sql == (
        'WITH big AS (SELECT orders.id FROM orders WHERE orders.qty > 1)\n'
        'SELECT o.id, c.name, count(*)\n'
        'FROM orders AS o\n'
        'INNER JOIN customers AS c ON c.id = o.cid\n'
        'LEFT JOIN big ON big.id = o.id\n'
        'WHERE o.qty > 1 AND o.id IN (SELECT big.id FROM big)\n'
        'GROUP BY o.id, c.name\n'
        'HAVING count(*) > 1\n'
        'ORDER BY o.id DESC\n'
        'LIMIT 10\n'
        'OFFSET 5'
    )
    assert policy.rewrite('select id from orders union all select id from customers order by 1').sql == (
        '(SELECT orders.id FROM orders)\nUNION ALL\n(SELECT customers.id FROM customers)\nORDER BY 1'
    )
    assert policy.rewrite("insert into orders (a, b) values (1, 'x'), (2, 'y') returning id").sql == (
        "INSERT INTO orders (a, b)\nVALUES (1, 'x'), (2, 'y')\nRETURNING orders.id"
    )
    assert policy.rewrite('update orders set a = 1, b = b + 1 where id = 1 returning a').sql == (
        'UPDATE orders\nSET a = 1, b = orders.b + 1\nWHERE orders.id = 1\nRETURNING orders.a'
    )
    assert policy.rewrite('delete from orders where id = 1').sql == 'DELETE FROM orders\nWHERE orders.id = 1'
    assert policy.rewrite('select 1').sql == 'SELECT 1'

    dense = Policy(Select('orders', ['id', 'qty', 'cid', 'a', 'b']), layout='dense')
    assert dense.rewrite('select id from orders where qty > 1 order by id').sql == (
        'SELECT orders.id FROM orders WHERE orders.qty > 1 ORDER BY orders.id'
    )
    with pytest.raises(P14gError, match='unknown layout "wide"') as exc_info:
        Policy(layout='wide')  # pyright: ignore[reportArgumentType]
    assert exc_info.value.kind == 'config'


def test_parentheses():
    policy = Policy(Select('t', ['a', 'b', 'c']), layout='dense')

    def where(condition: str) -> str:
        return policy.rewrite(f'select a from t where {condition}').sql.removeprefix('SELECT t.a FROM t WHERE ')

    # a condition with the clause to itself has none, nor does a chain of AND or of OR
    assert where('a = 1') == 't.a = 1'
    assert where('a = 1 and b = 2 and c = 3') == 't.a = 1 AND t.b = 2 AND t.c = 3'
    assert where('a = 1 and (b = 2 and c = 3)') == 't.a = 1 AND t.b = 2 AND t.c = 3'
    assert where('a = 1 or b = 2 or c = 3') == 't.a = 1 OR t.b = 2 OR t.c = 3'
    # mixing AND and OR keeps them, whichever way the input grouped it
    assert where('a = 1 or b = 2 and c = 3') == 't.a = 1 OR (t.b = 2 AND t.c = 3)'
    assert where('(a = 1 or b = 2) and c = 3') == '(t.a = 1 OR t.b = 2) AND t.c = 3'
    # comparisons and tests stand bare beside AND and OR, anything else is wrapped
    assert where("a is null and b in (1, 2) and c like 'x' and exists (select 1)") == (
        "t.a IS NULL AND t.b IN (1, 2) AND t.c LIKE 'x' AND EXISTS (SELECT 1)"
    )
    assert where('not a = 1 and b between 1 and 2 and not exists (select 1) and (a < b) = c') == (
        '(NOT (t.a = 1)) AND (t.b BETWEEN 1 AND 2) AND (NOT EXISTS (SELECT 1)) AND (t.a < t.b) = t.c'
    )
    # the operands of everything else are always wrapped, so precedence is never in question
    assert where('a + b * c > (a - b) - c') == '(t.a + (t.b * t.c)) > ((t.a - t.b) - t.c)'
    assert where('a = -1 and - a = b') == 't.a = (- 1) AND (- t.a) = t.b'
    # and so does each select item and each function argument
    assert policy.rewrite("select a + 1, -a, a = 1 and b = 2, lower(a || 'x') from t").sql == (
        "SELECT t.a + 1, - t.a, t.a = 1 AND t.b = 2, lower(t.a || 'x') FROM t"
    )


def test_qualify_builtins():
    sql = "select count(*), lower(a), left(a, 1), position('x' in a), app.f(a) from t"
    plain = Policy(Select('t', ['a']), functions=['app.f'], layout='dense')
    assert plain.rewrite(sql).sql == (
        """SELECT count(*), lower(t.a), left(t.a, 1), "position"(t.a, 'x'), app.f(t.a) FROM t"""
    )
    qualified = Policy(Select('t', ['a']), functions=['app.f'], layout='dense', qualify_builtins=True)
    assert qualified.rewrite(sql).sql == (
        "SELECT pg_catalog.count(*), pg_catalog.lower(t.a), pg_catalog.left(t.a, 1), pg_catalog.position(t.a, 'x'), "
        'app.f(t.a) FROM t'
    )
    with pytest.raises(TypeError):
        Policy(qualify_builtins='yes')  # pyright: ignore[reportArgumentType]


def test_filter():
    def org(context: dict[str, Any]) -> tuple[LiteralString, dict[str, Any]]:
        return 'org = :org_id and deleted_at is null', {'org_id': context['org_id']}

    policy = DensePolicy(
        Select('orders', columns=['id', 'qty'], filter=org),
        Select('customers', ['id', 'name']),
        Insert('orders', columns=['qty'], extra=lambda context: {'org': context['org_id']}),
        Update('orders', columns=['qty', 'org'], filter=org),
        Delete('orders', filter=org),
    )
    context = {'org_id': 42}
    orders = '(SELECT orders.id, orders.qty FROM orders WHERE orders.org = 42 AND orders.deleted_at IS NULL)'
    # a filtered table is read through a subquery that applies the filter
    assert policy.rewrite('select * from orders where qty > 1', context=context).sql == (
        f'SELECT orders.id, orders.qty FROM {orders} AS orders WHERE orders.qty > 1'
    )
    assert policy.rewrite('select c.name from customers c left join orders o on o.id = c.id', context=context).sql == (
        f'SELECT c.name FROM customers AS c LEFT JOIN {orders} AS o ON o.id = c.id'
    )
    # a write takes it as part of its WHERE
    assert policy.rewrite('update orders set qty = 1 where id = 7 or true', context=context).sql == (
        'UPDATE orders SET qty = 1 WHERE orders.org = 42 AND orders.deleted_at IS NULL AND (orders.id = 7 OR TRUE)'
    )
    assert policy.rewrite('delete from orders where id = 7', context=context).sql == (
        'DELETE FROM orders WHERE orders.org = 42 AND orders.deleted_at IS NULL AND orders.id = 7'
    )
    assert policy.rewrite('insert into orders (qty) values (1)', context=context).sql == (
        'INSERT INTO orders (qty, org) VALUES (1, 42)'
    )
    # the filter's columns are not the statement's to read or to set
    with pytest.raises(P14gError, match='column "org" is not allowed'):
        policy.rewrite('select org from orders', context=context)
    with pytest.raises(P14gError, match="is used by the policy's filter and cannot be set") as exc_info:
        policy.rewrite('update orders set org = 1 where id = 7', context=context)
    assert exc_info.value.kind == 'denied'
    assert policy.grants('app', context=context) == [
        'GRANT SELECT ("id", "name") ON "customers" TO "app"',
        'GRANT SELECT ("id", "qty", "deleted_at", "org") ON "orders" TO "app"',
        'GRANT INSERT ("qty", "org") ON "orders" TO "app"',
        'GRANT UPDATE ("qty", "org") ON "orders" TO "app"',
        'GRANT DELETE ON "orders" TO "app"',
    ]


def test_filter_values():
    def where(sql: str, values: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        def filter(context: Any) -> Any:
            return sql if values is None else (sql, values)

        safe = DensePolicy(Select('t', ['a'], filter=filter), **kwargs).rewrite('select a from t')
        assert safe.sql.startswith('SELECT t.a FROM (SELECT t.a FROM t WHERE ') and safe.sql.endswith(') AS t')
        where = safe.sql.removeprefix('SELECT t.a FROM (SELECT t.a FROM t WHERE ').removesuffix(') AS t')
        return (where, safe.params) if kwargs else where

    # values are written as literals, whatever is in them
    assert where('a = :v', {'v': "x' OR '1'='1"}) == "t.a = 'x'' OR ''1''=''1'"
    assert where('a = :v', {'v': 'a\\b'}) == "t.a = E'a\\\\b'"
    assert where(
        'a = :i and b = :f and c = :t and d is not distinct from :n', {'i': -3, 'f': 1.5, 't': True, 'n': None}
    ) == ('t.a = (- 3) AND t.b = 1.5 AND t.c = TRUE AND (t.d IS NOT DISTINCT FROM NULL)')
    # a list is the items of IN
    assert where('a in (:xs) and b not in (:ys)', {'xs': [1, 2], 'ys': ['x', 'y']}) == (
        "t.a IN (1, 2) AND t.b NOT IN ('x', 'y')"
    )
    # a cast applies to the bound value
    assert where('created > :since::timestamptz', {'since': '2026-01-01'}) == (
        "t.created > CAST('2026-01-01' AS timestamp with time zone)"
    )
    # a filter with nothing to bind can be returned, or given, as a string
    assert where('deleted_at is null') == 't.deleted_at IS NULL'
    assert DensePolicy(Select('t', ['a'], filter='not archived')).rewrite('select a from t').sql == (
        'SELECT t.a FROM (SELECT t.a FROM t WHERE NOT t.archived) AS t'
    )
    # with parameters, strings from the filter are parameters
    assert where('a = :s and b = :n', {'s': 'x', 'n': 1}, literals='params') == ('t.a = $1 AND t.b = 1', ['x'])


def test_filter_context():
    seen: list[Any] = []

    def filter(context: Any) -> tuple[LiteralString, dict[str, Any]]:
        seen.append(context)
        return 'org = :org', {'org': context}

    policy = DensePolicy(Select('t', ['a'], filter=filter), Delete('t', filter=filter))
    assert policy.rewrite('select t1.a from t t1 join t t2 on true', context=5).sql == (
        'SELECT t1.a FROM (SELECT t.a FROM t WHERE t.org = 5) AS t1 INNER JOIN (SELECT t.a FROM t WHERE t.org = 5) AS t2 '
        'ON TRUE'
    )
    # called for each use of the table
    assert seen == [5, 5]
    assert policy.rewrite('delete from t where a = 1', context=6).sql == 'DELETE FROM t WHERE t.org = 6 AND t.a = 1'


FILTER_ERRORS: list[tuple[Any, str, type[Exception] | None]] = [
    (('a = :x', {}), 'invalid filter for table "t": the filter uses :x but no value was given for it', None),
    (('a = :x', {'x': [1]}), 'invalid filter for table "t": :x is a list, which can only be used as IN (:x)', None),
    (
        ('a in (:x)', {'x': []}),
        'invalid filter for table "t": :x is an empty list, and IN () is not valid SQL',
        None,
    ),
    (('a in (select 1)', {}), 'invalid filter for table "t": a subquery in a filter is not supported', None),
    (('a = 1; drop table t', {}), 'invalid filter for table "t": expected one expression, found ; after it', None),
    (('other.a = 1', {}), 'invalid filter for table "t": other.a is a column of another table', None),
    (42, 'callback failed: TypeError: a filter must return (sql, values) or sql', TypeError),
    (('a = 1', [1]), 'callback failed: TypeError: a filter must return (sql, values) or sql', TypeError),
    (
        ('a = :x', {'x': object()}),
        'callback failed: TypeError: expected None, bool, int, float or str, not object',
        TypeError,
    ),
    # a tuple is not a list, and not one value either
    (
        ('a in (:x)', {'x': (1, 2)}),
        'callback failed: TypeError: expected None, bool, int, float or str, not tuple',
        TypeError,
    ),
    (
        ('a = 1', {1: 2}),
        "callback failed: TypeError: the keys of a filter's values must be placeholder names",
        TypeError,
    ),
]


@pytest.mark.parametrize('returned,message,cause', FILTER_ERRORS)
def test_filter_errors(returned: Any, message: str, cause: type[Exception] | None):
    policy = DensePolicy(
        Select('t', ['a', 'b'], filter=lambda context: returned),
        Update('t', filter=lambda context: returned),
        Delete('t', filter=lambda context: returned),
    )
    # a filter that cannot be used rejects the statement, it is never left out
    for sql in 'select a from t', 'update t set a = 1 where b = 2', 'delete from t where b = 2':
        with pytest.raises(P14gError) as exc_info:
            policy.rewrite(sql)
        assert str(exc_info.value) == message
        assert exc_info.value.kind == 'callback'
        assert type(exc_info.value.__cause__) is (cause or type(None))


def test_filter_raises_and_arguments():
    def broken(context: Any) -> Any:
        raise KeyError('org_id')

    with pytest.raises(P14gError, match="callback failed: KeyError: 'org_id'") as exc_info:
        DensePolicy(Select('t', ['a'], filter=broken)).rewrite('select a from t')
    assert isinstance(exc_info.value.__cause__, KeyError)

    for rule in partial(Select, columns=['a']), Update, Delete:
        with pytest.raises(TypeError, match=r'filter must be a callable returning \(sql, values\), or a str'):
            rule('t', filter=42)  # pyright: ignore[reportArgumentType, reportCallIssue]
    with pytest.raises(P14gError, match='there is more than one delete rule for table "t"') as exc_info:
        DensePolicy(Delete('t'), Delete('t', allow_unfiltered=True))
    assert exc_info.value.kind == 'config'


@dataclass
class Request:
    tenant_id: int


def by_tenant(request: Request) -> tuple[LiteralString, dict[str, int]]:
    return 'tenant_id = :tenant_id', {'tenant_id': request.tenant_id}


def test_context_type():
    # not DensePolicy: functools.partial loses the type parameter
    policy = Policy(
        Select('orders', columns=['id'], filter=by_tenant),
        # rules with no callback take any context
        Insert('orders', columns=['qty']),
        Delete('orders'),
        layout='dense',
    )
    assert_type(policy, Policy[Request])
    assert policy.rewrite('select id from orders', context=Request(42)).sql == (
        'SELECT orders.id FROM (SELECT orders.id FROM orders WHERE orders.tenant_id = 42) AS orders'
    )
    assert policy.grants('app', context=Request(42)) == [
        'GRANT SELECT ("id", "tenant_id") ON "orders" TO "app"',
        'GRANT INSERT ("qty") ON "orders" TO "app"',
        'GRANT DELETE ON "orders" TO "app"',
    ]
    # the context is required, and must be a Request
    with pytest.raises(P14gError, match="callback failed: AttributeError: 'NoneType' object has no attribute"):
        policy.rewrite('select id from orders')  # pyright: ignore[reportCallIssue]
    with pytest.raises(P14gError, match="callback failed: AttributeError: 'int' object has no attribute"):
        policy.rewrite('select id from orders', context=42)  # pyright: ignore[reportArgumentType, reportCallIssue]

    # a policy whose callbacks take nothing in particular needs no context
    assert_type(Policy(Select('orders', ['id'])), Policy[Any])
    Policy(Select('orders', ['id'])).rewrite('select id from orders')


def test_context_type_subscript():
    """The generic classes can be subscripted at run time, for annotations evaluated then."""
    aliases: list[tuple[object, type]] = [
        (Policy[Request], Policy),
        (Select[Request], Select),
        (Insert[Request], Insert),
        (Update[Request], Update),
        (Delete[Request], Delete),
    ]
    for alias, cls in aliases:
        assert get_origin(alias) is cls
        assert get_args(alias) == (Request,)
    policy: Policy[Request] = Policy[Request](Select('orders', ['id'], filter=by_tenant))
    assert policy.rewrite('select 1 from orders', context=Request(1)).sql.endswith(
        'WHERE orders.tenant_id = 1) AS orders'
    )
