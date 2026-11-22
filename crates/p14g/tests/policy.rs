//! Policy options and the public API, beyond what the case files cover.

mod common;

use std::thread;

use p14g::{
    Delete, Dialect, Error, ErrorKind, Filter, Insert, Layout, Limits, Literals, Mapper, Op, Policy, PolicyBuilder,
    QuoteIdentifiers, Select, Star, StatementKind, Update,
    ast::{Expr, Function, Ident, Literal, Table},
    functions,
};

/// A builder that writes each statement on one line, which is easier to compare against.
fn dense<C>() -> PolicyBuilder<C> {
    Policy::builder().layout(Layout::Dense)
}

fn orders() -> Select {
    Select::table("orders").columns(["id", "product", "qty"])
}

fn rewrite(policy: &Policy, sql: &str) -> String {
    policy.rewrite(sql, &()).unwrap_or_else(|e| panic!("{sql}: {e}")).sql
}

fn kind(policy: &Policy, sql: &str) -> ErrorKind {
    match policy.rewrite(sql, &()) {
        Ok(safe) => panic!("{sql} was accepted as {}", safe.sql),
        Err(e) => e.kind(),
    }
}

fn config_error<C>(result: Result<Policy<C>, Error>) -> String {
    match result {
        Ok(_) => panic!("the policy was built"),
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::Config);
            e.to_string()
        }
    }
}

#[test]
fn result_describes_the_statement() {
    let policy = common::policy();
    let safe = policy
        .rewrite(
            "select o.id from orders o join app.events e on e.id = o.id where o.id in (select id from customers)",
            &(),
        )
        .unwrap();
    assert_eq!(safe.kind, StatementKind::Select);
    assert_eq!(safe.tables, ["app.events", "customers", "orders"]);
    assert_eq!(safe.params, Vec::<String>::new());

    let safe = policy.rewrite("delete from orders where id = 1", &()).unwrap();
    assert_eq!(safe.kind, StatementKind::Delete);
    assert_eq!(safe.tables, ["orders"]);
}

#[test]
fn errors_say_where() {
    let policy = common::policy();
    // an error found while reading the statement points at the name or literal it is about
    let error = policy.rewrite("select id,\n  U&'x'\nfrom orders", &()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(error.message(), "this kind of literal is not supported");
    let location = error.location().unwrap();
    assert_eq!((location.line, location.column), (2, 3));
    assert_eq!(
        error.to_string(),
        "this kind of literal is not supported at line 2, column 3"
    );

    let error = policy
        .rewrite("select id from orders where\n qty @@ 1", &())
        .unwrap_err();
    assert_eq!(error.to_string(), "this operator is not supported at line 2, column 2");

    let error = policy.rewrite("select 'abc", &()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(error.location().map(|l| (l.line, l.column)), Some((1, 8)));

    // an error from the policy names what was refused, but has no position
    let error = policy
        .rewrite("select id,\n  pg_sleep(1)\nfrom orders", &())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Denied);
    assert_eq!(error.to_string(), "function \"pg_sleep\" is not allowed");
    assert_eq!(error.location(), None);
}

#[test]
fn allow_restricts_statement_kinds() {
    let policy = common::policy();
    let select_only = Some(&[StatementKind::Select][..]);
    assert!(policy.rewrite_kinds("select id from orders", &(), select_only).is_ok());
    let error = policy
        .rewrite_kinds("delete from orders where id = 1", &(), select_only)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Denied);
    assert_eq!(error.message(), "DELETE statements are not allowed here");
    assert!(policy.rewrite_kinds("select id from orders", &(), Some(&[])).is_err());
}

#[test]
fn star_behaviour() {
    let build = |star| -> Policy {
        dense()
            .select(orders())
            .select(Select::table("v"))
            .star_behaviour(star)
            .build()
            .unwrap()
    };

    let expand = build(Star::Expand);
    assert_eq!(
        rewrite(&expand, "select * from orders"),
        "SELECT orders.id, orders.product, orders.qty FROM orders"
    );
    assert_eq!(rewrite(&expand, "select * from v"), "SELECT v.* FROM v");
    assert_eq!(
        rewrite(&expand, "select * from orders o join v on v.id = o.id"),
        "SELECT o.id, o.product, o.qty, v.* FROM orders AS o INNER JOIN v ON v.id = o.id"
    );
    assert_eq!(
        rewrite(&expand, "select count(*) from orders"),
        "SELECT count(*) FROM orders"
    );

    let allow = build(Star::Allow);
    assert_eq!(rewrite(&allow, "select * from v"), "SELECT * FROM v");
    assert_eq!(rewrite(&allow, "select v.* from v"), "SELECT v.* FROM v");
    assert_eq!(kind(&allow, "select * from orders"), ErrorKind::Denied);
    assert_eq!(
        kind(&allow, "select * from orders o join v on v.id = o.id"),
        ErrorKind::Denied
    );
    assert_eq!(
        rewrite(&allow, "select v.* from orders o join v on v.id = o.id"),
        "SELECT v.* FROM orders AS o INNER JOIN v ON v.id = o.id"
    );
    // a subquery that kept its star has columns p14g cannot list, and is treated like the view under it
    assert_eq!(
        rewrite(&allow, "select x.anything from (select * from v) x"),
        "SELECT x.anything FROM (SELECT * FROM v) AS x"
    );

    let reject = build(Star::Reject);
    assert_eq!(kind(&reject, "select * from v"), ErrorKind::Denied);
    assert_eq!(kind(&reject, "select v.* from v"), ErrorKind::Denied);
    assert_eq!(rewrite(&reject, "select count(*) from v"), "SELECT count(*) FROM v");
}

#[test]
fn rules_for_one_table_are_alternatives() {
    let policy: Policy = dense()
        .select(Select::table("t").columns(["a"]))
        .select(Select::table("t").columns(["b"]))
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&policy, "select a from t where a = 1"),
        "SELECT t.a FROM t WHERE t.a = 1"
    );
    assert_eq!(
        rewrite(&policy, "select b from t where b < 1"),
        "SELECT t.b FROM t WHERE t.b < 1"
    );
    // each column is allowed by a rule, but no one rule allows both
    assert_eq!(kind(&policy, "select a, b from t"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select a from t where b > 1"), ErrorKind::Denied);
    // two instances of the table can each use a different rule
    assert!(
        policy
            .rewrite("select t1.a from t t1 where t1.a = (select max(t2.b) from t t2)", &())
            .is_ok()
    );
    assert!(
        policy
            .rewrite(
                "select (select max(t2.b) from t t2 where t2.b > 0), t1.a from t t1",
                &()
            )
            .is_ok()
    );
    // star takes the columns of the rule that fits the rest of the query
    assert_eq!(
        rewrite(&policy, "select * from t where b > 1"),
        "SELECT t.b FROM t WHERE t.b > 1"
    );
}

#[test]
fn operators() {
    let policy: Policy = dense().select(orders()).operators([Op::Eq, Op::And]).build().unwrap();
    assert!(
        policy
            .rewrite("select id from orders where id = 1 and qty = 2", &())
            .is_ok()
    );
    assert_eq!(
        kind(&policy, "select id from orders where id = 1 or qty = 2"),
        ErrorKind::Denied
    );
    // the list is for the whole statement: a column that comes through a subquery or a CTE, and no column
    for sql in [
        "select x from (select id as x from orders) d where x < 1",
        "with d as (select id, qty from orders) select id from d where id < 1 or qty = 2",
        "select id from orders where id = (select max(qty) from orders o where o.qty > 0)",
        "select id from orders union select qty from orders where qty + 1 = 2",
        "select 1 + 1",
    ] {
        assert_eq!(kind(&policy, sql), ErrorKind::Denied, "{sql}");
    }
    assert_eq!(
        kind(&policy, "select id from orders limit 1 offset 1 + 1"),
        ErrorKind::Unsupported
    );

    let regex: Policy = dense()
        .select(orders())
        .operators(Op::ALL.iter().copied())
        .build()
        .unwrap();
    assert_eq!(
        rewrite(
            &regex,
            "select id from orders where product ~ '^t' and product similar to 't%'"
        ),
        "SELECT orders.id FROM orders WHERE (orders.product ~ '^t') AND orders.product SIMILAR TO 't%'"
    );

    for op in Op::ALL {
        assert_eq!(Op::parse(op.as_str()).unwrap(), *op);
    }
    assert_eq!(Op::parse("<>").unwrap(), Op::NotEq);
    assert_eq!(Op::parse(" LIKE ").unwrap(), Op::Like);
    assert_eq!(Op::parse("xor").unwrap_err().kind(), ErrorKind::Config);
}

/// Each operator is refused when it is the one left out of the list, and needs nothing but itself.
#[test]
fn every_operator_is_checked() {
    let cases: &[(Op, &[&str])] = &[
        (Op::Eq, &["qty = 1"]),
        (Op::NotEq, &["qty != 1", "qty <> 1"]),
        (Op::Lt, &["qty < 1"]),
        (Op::LtEq, &["qty <= 1"]),
        (Op::Gt, &["qty > 1"]),
        (Op::GtEq, &["qty >= 1"]),
        (Op::And, &["true and false"]),
        (Op::Or, &["true or false"]),
        (Op::Not, &["not true"]),
        (Op::Plus, &["qty + 1", "+qty"]),
        (Op::Minus, &["qty - 1", "-qty"]),
        (Op::Multiply, &["qty * 2"]),
        (Op::Divide, &["qty / 2"]),
        (Op::Modulo, &["qty % 2"]),
        (Op::Concat, &["product || 'x'"]),
        (
            Op::Like,
            &[
                "product like 'a%'",
                "product not like 'a%'",
                "product like 'a!%' escape '!'",
            ],
        ),
        (Op::ILike, &["product ilike 'a%'", "product not ilike 'a%'"]),
        (
            Op::SimilarTo,
            &["product similar to 'a%'", "product not similar to 'a%'"],
        ),
        (
            Op::Regex,
            &["product ~ 'a'", "product ~* 'a'", "product !~ 'a'", "product !~* 'a'"],
        ),
        (
            Op::In,
            &["qty in (1, 2)", "qty not in (1, 2)", "qty in (select id from orders)"],
        ),
        (Op::Between, &["qty between 1 and 2", "qty not between 1 and 2"]),
        (
            Op::Is,
            &[
                "qty is null",
                "qty is not null",
                "(qty is null) is true",
                "(qty is null) is not false",
            ],
        ),
        (
            Op::IsDistinctFrom,
            &["qty is distinct from 1", "qty is not distinct from 1"],
        ),
        (
            Op::Json,
            &["product -> 'a'", "product ->> 'a'", "product #> 'a'", "product #>> 'a'"],
        ),
        (Op::Contains, &["product @> 'a'", "product <@ 'a'"]),
    ];
    let covered: Vec<Op> = cases.iter().map(|(op, _)| *op).collect();
    assert_eq!(covered, Op::ALL, "a case for every operator, in order");

    for &(op, expressions) in cases {
        let only: Policy = dense().select(orders()).operators([op]).build().unwrap();
        let without: Policy = dense()
            .select(orders())
            .operators(Op::ALL.iter().copied().filter(|other| *other != op))
            .build()
            .unwrap();
        for expression in expressions {
            let sql = format!("select {expression} from orders");
            assert!(only.rewrite(&sql, &()).is_ok(), "{sql} needs more than {op:?}");
            let error = without.rewrite(&sql, &()).expect_err(&sql);
            assert_eq!(error.kind(), ErrorKind::Denied, "{sql}");
            assert_eq!(
                error.message(),
                format!("operator not allowed: {}", op.as_str()),
                "{sql}"
            );
        }
    }

    // syntax that is not an operator in the list needs none
    let none: Policy = dense().select(orders()).operators([]).build().unwrap();
    for sql in [
        "select cast(qty as text), qty::text from orders",
        "select case when true then 1 else 2 end from orders",
        "select coalesce(qty, 0), lower(product), count(*) from orders group by qty, product",
        "select id from orders where exists (select 1 from orders o)",
    ] {
        assert!(none.rewrite(sql, &()).is_ok(), "{sql}");
    }
}

/// An operator is checked wherever an expression can be written.
#[test]
fn operators_are_checked_in_every_clause() {
    let policy: Policy = dense()
        .select(orders())
        .select(Select::table("customers").columns(["id", "name"]))
        .insert(Insert::table("orders").columns(["product", "qty"]))
        .update(Update::table("orders").columns(["qty"]))
        .delete(Delete::table("orders"))
        .operators([Op::Eq, Op::And])
        .build()
        .unwrap();

    // every statement is allowed with `=` where it has `<`
    for sql in [
        "select qty < 1 from orders",
        "select id from orders where qty < 1",
        "select id from orders where id = 1 and qty < 1",
        "select o.id from orders o join customers c on c.id < o.id",
        "select o.id from orders o left join customers c on c.id = o.id and c.id < 1",
        "select count(*) from orders group by qty < 1",
        "select qty from orders group by qty having count(*) < 1",
        "select id from orders order by qty < 1",
        "select case when qty < 1 then 1 else 2 end from orders",
        "select case qty when 1 then id < 1 end from orders",
        "select coalesce(qty < 1, true) from orders",
        "select lower(product) < 'a' from orders",
        "select count(*) filter (where qty < 1) from orders",
        "select sum(qty) over (partition by qty < 1) from orders",
        "select sum(qty) over (order by qty < 1) from orders",
        "select string_agg(product, ',' order by qty < 1) from orders",
        "select cast(qty < 1 as text) from orders",
        "select nullif(qty < 1, true) from orders",
        "select id from orders where id = 1 and (qty = 2 and (id = 3 and qty < 4))",
        "select id from (select id from orders where qty < 1) d",
        "select d.x from (select qty < 1 as x from orders) d",
        "select x from (select qty as x from orders) d where x < 1",
        "select id from orders where id = (select max(id) from orders o where o.qty < 1)",
        "select id from orders where exists (select 1 from customers c where c.id < orders.id)",
        "select (select c.id < 1 from customers c) from orders",
        "with d as (select id from orders where qty < 1) select id from d",
        "with d as (select id, qty from orders) select id from d where qty < 1",
        "select id from orders union select id from customers where id < 1",
        "select id from orders where qty < 1 union all select id from customers",
        "insert into orders (product, qty) values ('a', 1 < 2)",
        "insert into orders (product, qty) values ('a', 1) returning qty < 1",
        "update orders set qty = qty < 1 where id = 1",
        "update orders set qty = 1 where id < 1",
        "update orders set qty = 1 where id = 1 returning qty < 1",
        "update orders set qty = 1 where id = (select max(c.id) from customers c where c.id < 1)",
        "delete from orders where id < 1",
        "delete from orders where id = 1 returning qty < 1",
    ] {
        let error = policy.rewrite(sql, &()).expect_err(sql);
        assert_eq!(error.kind(), ErrorKind::Denied, "{sql}");
        assert_eq!(error.message(), "operator not allowed: <", "{sql}");
        let allowed = sql.replace('<', "=");
        assert!(policy.rewrite(&allowed, &()).is_ok(), "{allowed}");
    }
}

/// A filter is written by the policy author, so the operator list does not apply to it.
#[test]
fn operators_do_not_restrict_filters() {
    let policy: Policy = dense()
        .select(
            Select::table("docs")
                .columns(["id"])
                .filter(|()| Filter::new("org < 5 or title ~ '^a'")),
        )
        .operators([Op::Eq])
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&policy, "select id from docs where id = 1"),
        "SELECT docs.id FROM (SELECT docs.id FROM docs WHERE docs.org < 5 OR (docs.title ~ '^a')) AS docs \
         WHERE docs.id = 1"
    );
    assert_eq!(kind(&policy, "select id from docs where id < 1"), ErrorKind::Denied);
}

#[test]
fn functions_allow_and_deny() {
    let policy: Policy = dense()
        .select(orders())
        .functions(["app.order_total", "repeat"])
        .deny_functions(["random", "pg_catalog.now"])
        .build()
        .unwrap();
    assert_eq!(
        rewrite(
            &policy,
            "select app.order_total(id), repeat(product, 2), lower(product) from orders"
        ),
        "SELECT app.order_total(orders.id), repeat(orders.product, 2), lower(orders.product) FROM orders"
    );
    assert_eq!(kind(&policy, "select random()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select now()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select pg_catalog.now()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select order_total(id) from orders"), ErrorKind::Denied);
    assert_eq!(
        kind(&policy, "select other.order_total(id) from orders"),
        ErrorKind::Denied
    );

    let none: Policy = dense()
        .select(orders())
        .default_functions(false)
        .functions(["count"])
        .build()
        .unwrap();
    assert!(none.rewrite("select count(*) from orders", &()).is_ok());
    assert_eq!(kind(&none, "select lower(product) from orders"), ErrorKind::Denied);
    assert_eq!(kind(&none, "select coalesce(qty, 0) from orders"), ErrorKind::Denied);
    assert_eq!(kind(&none, "select extract(year from current_date)"), ErrorKind::Denied);
    assert_eq!(kind(&none, "select trim(product) from orders"), ErrorKind::Denied);

    let message = config_error(dense::<()>().deny_functions(["pg_sleep"]).build());
    assert_eq!(
        message,
        "cannot deny function \"pg_sleep\": it is not an allowed function"
    );
    config_error(dense::<()>().default_functions(false).deny_functions(["count"]).build());
}

#[test]
fn every_default_function_is_listed_once() {
    let mut names: Vec<&str> = functions::defaults().collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total);
    for name in names {
        assert_eq!(name, name.to_ascii_lowercase());
        assert!(!name.starts_with("pg_"));
    }
}

#[test]
fn config_errors() {
    config_error(dense::<()>().select(Select::table("")).build());
    config_error(dense::<()>().select(Select::table("a.b.c")).build());
    config_error(dense::<()>().select(Select::table("t").columns(["a", "a"])).build());
    config_error(dense::<()>().select(Select::table("t").columns([""])).build());
    config_error(dense::<()>().select(Select::table("x".repeat(64))).build());
    config_error(dense::<()>().functions(["a.b.c"]).build());
    config_error(dense::<()>().update(Update::table("t").columns(["a\0"])).build());
    assert_eq!(Dialect::parse("oracle").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Star::parse("maybe").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Literals::parse("bind").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(StatementKind::parse("merge").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Dialect::parse("PostgreSQL").unwrap(), Dialect::Postgres);
}

#[test]
fn rule_names_are_exact() {
    let policy: Policy = dense().select(Select::table("Orders").columns(["Id"])).build().unwrap();
    // unquoted names fold to lower case, as they would in Postgres, so only the quoted spelling matches
    assert_eq!(kind(&policy, "select id from orders"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select Id from Orders"), ErrorKind::Denied);
    assert_eq!(
        rewrite(&policy, r#"select "Id" from "Orders""#),
        r#"SELECT "Orders"."Id" FROM "Orders""#
    );
}

#[test]
fn limits() {
    let build = |limits: Limits| -> Policy { dense().select(orders()).limits(limits).build().unwrap() };
    let tight = build(Limits {
        max_sql_bytes: 200,
        max_depth: 8,
        max_nodes: 40,
        max_joins: 1,
        max_subqueries: 1,
        max_set_operations: 1,
        max_in_list: 3,
        max_projection: 3,
        max_values_rows: 2,
    });
    assert!(
        tight
            .rewrite("select id from orders where id in (1, 2, 3)", &())
            .is_ok()
    );
    for sql in [
        format!("select id from orders where product = '{}'", "x".repeat(200)),
        "select id from orders where id in (1, 2, 3, 4)".to_owned(),
        "select id, id, id, id from orders".to_owned(),
        "select a.id from orders a join orders b on a.id = b.id join orders c on c.id = a.id".to_owned(),
        "select a.id from orders a, orders b, orders c".to_owned(),
        "select id from orders where id in (select id from orders where id in (select id from orders))".to_owned(),
        "select id from orders union select id from orders union select id from orders".to_owned(),
        "select ((((((((((id)))))))))) from orders".to_owned(),
        "select id from orders where id = 1 or id = 2 or id = 3 or id = 4 or id = 5 or id = 6 or id = 7".to_owned(),
    ] {
        assert_eq!(kind(&tight, &sql), ErrorKind::Limit, "{sql}");
    }

    let policy = build(Limits::default());
    let huge = format!("select id from orders where product = '{}'", "x".repeat(100_000));
    assert_eq!(kind(&policy, &huge), ErrorKind::Limit);
    let many = format!("select id from orders where id in ({})", vec!["1"; 6_000].join(","));
    assert_eq!(kind(&policy, &many), ErrorKind::Limit);

    let rows: Policy = dense()
        .insert(Insert::table("orders"))
        .limits(Limits {
            max_values_rows: 2,
            ..Limits::default()
        })
        .build()
        .unwrap();
    assert!(rows.rewrite("insert into orders (qty) values (1), (2)", &()).is_ok());
    assert_eq!(
        kind(&rows, "insert into orders (qty) values (1), (2), (3)"),
        ErrorKind::Limit
    );

    // RETURNING is a select list too
    let writes: Policy = dense()
        .select(orders())
        .insert(Insert::table("orders"))
        .update(Update::table("orders").columns(["qty"]))
        .delete(Delete::table("orders"))
        .limits(Limits {
            max_projection: 3,
            ..Limits::default()
        })
        .build()
        .unwrap();
    assert!(
        writes
            .rewrite("delete from orders where id = 1 returning id, id, id", &())
            .is_ok()
    );
    for sql in [
        "insert into orders (qty) values (1) returning id, id, id, id",
        "update orders set qty = 1 returning id, id, id, id",
        "delete from orders where id = 1 returning id, id, id, id",
    ] {
        assert_eq!(kind(&writes, sql), ErrorKind::Limit, "{sql}");
    }

    config_error(
        dense::<()>()
            .limits(Limits {
                max_depth: 0,
                ..Limits::default()
            })
            .build(),
    );
}

#[test]
fn star_expansion_limit() {
    let build = |max_projection: usize| -> Policy {
        dense()
            .select(orders())
            .limits(Limits {
                max_projection,
                ..Limits::default()
            })
            .build()
            .unwrap()
    };
    // `*` on orders is 3 columns, so 3 of them are 9 items: the limit counts the expanded list
    let nine = "select o.*, o.*, o.* from orders o";
    assert!(build(9).rewrite(nine, &()).is_ok());
    assert_eq!(kind(&build(8), nine), ErrorKind::Limit);

    // each derived table multiplies the columns of the one below: 40 stars over 3 levels would be 3 * 40^4
    // columns, and expanding them all ran out of memory before the limit was checked
    let mut nested = format!("select {} from orders o", vec!["o.*"; 40].join(", "));
    for level in 1..=3 {
        let stars = vec![format!("a{level}.*"); 40].join(", ");
        nested = format!("select {stars} from ({nested}) a{level}");
    }
    assert!(nested.len() < 1_000);
    assert_eq!(kind(&build(200), &nested), ErrorKind::Limit);
}

#[test]
fn max_rows() {
    let policy: Policy = dense().select(orders()).max_rows(Some(100)).build().unwrap();
    assert_eq!(
        rewrite(&policy, "select id from orders"),
        "SELECT orders.id FROM orders LIMIT 100"
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 5"),
        "SELECT orders.id FROM orders LIMIT 5"
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 500"),
        "SELECT orders.id FROM orders LIMIT 100"
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 99999999999999999999999"),
        "SELECT orders.id FROM orders LIMIT 100"
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 1.5"),
        "SELECT orders.id FROM orders LIMIT 100"
    );
    assert_eq!(
        rewrite(&policy, "select id from orders union select id from orders"),
        "(SELECT orders.id FROM orders) UNION (SELECT orders.id FROM orders) LIMIT 100"
    );
    assert_eq!(kind(&policy, "select id from orders limit $1"), ErrorKind::Denied);

    // lowering moves clauses outside parentheses onto the query inside them, as Postgres reads them, so the limit
    // to lower is always on the outermost query
    assert_eq!(
        rewrite(&policy, "(select id from orders limit 500)"),
        "SELECT orders.id FROM orders LIMIT 100"
    );
    assert_eq!(
        rewrite(&policy, "((select id from orders offset 2)) order by id"),
        "SELECT orders.id FROM orders ORDER BY orders.id LIMIT 100 OFFSET 2"
    );
    assert_eq!(
        rewrite(
            &policy,
            "(select id from orders limit 500) union (select id from orders)"
        ),
        "(SELECT orders.id FROM orders LIMIT 500) UNION (SELECT orders.id FROM orders) LIMIT 100"
    );
}

#[test]
fn params_are_numbered_after_the_input_placeholders() {
    let policy: Policy = dense()
        .select(orders())
        .insert(Insert::table("orders").extra(|()| [("note", "from the policy")]))
        .literals(Literals::Params)
        .build()
        .unwrap();
    let safe = policy
        .rewrite(
            "select id from orders where product = 'tea' and qty = $2 and product <> 'x''y' and id = $1 and qty > 5",
            &(),
        )
        .unwrap();
    assert_eq!(
        safe.sql,
        "SELECT orders.id FROM orders WHERE orders.product = $3 AND orders.qty = $2 AND orders.product <> $4 AND orders.id = $1 AND orders.qty > 5"
    );
    assert_eq!(safe.params, ["tea", "x'y"]);

    let safe = policy
        .rewrite("select date '2020-01-01', true, null, 1.5 from orders", &())
        .unwrap();
    assert_eq!(safe.sql, "SELECT CAST($1 AS date), TRUE, NULL, 1.5 FROM orders");
    assert_eq!(safe.params, ["2020-01-01"]);

    let safe = policy
        .rewrite("insert into orders (product) values ('a'), ('b')", &())
        .unwrap();
    assert_eq!(safe.sql, "INSERT INTO orders (product, note) VALUES ($1, $2), ($3, $4)");
    assert_eq!(safe.params, ["a", "from the policy", "b", "from the policy"]);
}

struct Tenant {
    id: i64,
    schema: &'static str,
}

#[test]
fn insert_extra() {
    let policy: Policy<Tenant> = dense()
        .select(Select::table("orders").columns(["id"]))
        .insert(
            Insert::table("orders")
                .columns(["product", "qty"])
                .extra(|tenant: &Tenant| [("tenant_id", tenant.id)]),
        )
        .insert(Insert::table("notes").try_extra(|tenant: &Tenant| {
            if tenant.id > 0 {
                Ok(vec![
                    ("flag".to_owned(), true.into()),
                    ("ratio".to_owned(), (-1.5).into()),
                    ("whole".to_owned(), 2.0.into()),
                    ("big".to_owned(), 1e300.into()),
                    ("small".to_owned(), 1e-7.into()),
                    ("label".to_owned(), "it's".into()),
                    ("nothing".to_owned(), Literal::Null.into()),
                    ("nan".to_owned(), f64::NAN.into()),
                ])
            } else {
                Err(Error::callback("no tenant"))
            }
        }))
        .insert(Insert::table("bad").extra(|_: &Tenant| [("", 1)]))
        .build()
        .unwrap();
    let tenant = Tenant { id: -7, schema: "t7" };
    let _ = tenant.schema;
    assert_eq!(
        policy
            .rewrite(
                "insert into orders (product, qty) values ('a', 1), ('b', 2) returning id",
                &tenant
            )
            .unwrap()
            .sql,
        "INSERT INTO orders (product, qty, tenant_id) VALUES ('a', 1, - 7), ('b', 2, - 7) RETURNING orders.id"
    );
    // the statement may not set a column the policy sets, whether or not the rule lists it
    let error = policy
        .rewrite("insert into orders (product, tenant_id) values ('a', 1)", &tenant)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Denied);

    let error = policy
        .rewrite("insert into notes (body) values ('x')", &tenant)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Callback);
    assert_eq!(error.message(), "no tenant");
    let error = policy
        .rewrite(
            "insert into notes (body, flag) values ('x', false)",
            &Tenant { id: 1, schema: "" },
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Denied);
    assert_eq!(
        policy
            .rewrite("insert into notes (body) values ('x')", &Tenant { id: 1, schema: "" })
            .unwrap()
            .sql,
        r#"INSERT INTO notes (body, flag, ratio, whole, big, small, "label", "nothing", nan) VALUES ('x', TRUE, - 1.5, 2.0, 1e300, 1e-7, 'it''s', NULL, CAST('NaN' AS double precision))"#
    );
    let error = policy.rewrite("insert into bad (x) values (1)", &tenant).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Callback);
}

#[test]
fn write_rules() {
    let policy: Policy = dense()
        .select(Select::table("t").columns(["id", "a"]))
        .insert(Insert::table("t"))
        .update(Update::table("t").columns(["a"]))
        .update(Update::table("t").columns(["b"]).allow_unfiltered(true))
        .delete(Delete::table("t").allow_unfiltered(true))
        .delete(Delete::table("u"))
        .build()
        .unwrap();
    assert_eq!(rewrite(&policy, "update t set b = 1"), "UPDATE t SET b = 1");
    // the rule that allows the unfiltered update is not the one that allows this column
    assert_eq!(kind(&policy, "update t set a = 1"), ErrorKind::Denied);
    assert_eq!(
        kind(&policy, "update t set a = 1, b = 2 where id = 1"),
        ErrorKind::Denied
    );
    assert_eq!(rewrite(&policy, "delete from t"), "DELETE FROM t");
    // `u` can be deleted from but not read, so a WHERE that names a column is refused
    assert_eq!(kind(&policy, "delete from u"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "delete from u where id = 1"), ErrorKind::Denied);
    assert_eq!(rewrite(&policy, "delete from u where true"), "DELETE FROM u WHERE TRUE");
    assert_eq!(kind(&policy, "delete from u where true returning *"), ErrorKind::Denied);
    assert_eq!(
        rewrite(&policy, "insert into t (anything) values (1)"),
        "INSERT INTO t (anything) VALUES (1)"
    );
    assert_eq!(
        rewrite(&policy, "update t as x set a = x.a + 1 where x.id = 1 returning x.*"),
        "UPDATE t AS x SET a = x.a + 1 WHERE x.id = 1 RETURNING x.id, x.a"
    );
    assert_eq!(kind(&policy, "update t set a = b where id = 1"), ErrorKind::Denied);
}

#[test]
fn group_by_names() {
    let policy: Policy = dense()
        .select(orders())
        .select(Select::table("v"))
        .select(Select::table("w"))
        .build()
        .unwrap();
    // a listed input column wins, as it does in Postgres
    assert_eq!(
        rewrite(
            &policy,
            "select lower(product) as product, count(*) from orders group by product"
        ),
        "SELECT lower(orders.product) AS product, count(*) FROM orders GROUP BY orders.product"
    );
    // no listed column of that name, and no table that could be hiding one: it can only be the alias
    assert_eq!(
        rewrite(&policy, "select lower(product) as p, count(*) from orders group by p"),
        "SELECT lower(orders.product) AS p, count(*) FROM orders GROUP BY 1"
    );
    // only all-column tables: either reading is allowed, so leave the choice to Postgres
    assert_eq!(
        rewrite(
            &policy,
            "select lower(v.x) as p, count(*) from v join w on w.id = v.id group by p"
        ),
        "SELECT lower(v.x) AS p, count(*) FROM v INNER JOIN w ON w.id = v.id GROUP BY p"
    );
    // a mix: the view might have a column called `p`, the restricted table must not be asked for one
    assert_eq!(
        kind(
            &policy,
            "select lower(v.x) as p from v join orders o on o.id = v.id group by p"
        ),
        ErrorKind::Denied
    );
    // ORDER BY always means the output column
    assert_eq!(
        rewrite(&policy, "select lower(product) as product from orders order by product"),
        "SELECT lower(orders.product) AS product FROM orders ORDER BY product"
    );
    assert_eq!(kind(&policy, "select id from orders order by 2"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select id from orders group by 0"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select * from orders order by 1"), ErrorKind::Denied);
    assert_eq!(
        kind(
            &policy,
            "select id from orders union select id from orders order by qty"
        ),
        ErrorKind::Denied
    );
}

#[test]
fn scoping() {
    let policy: Policy = dense()
        .select(orders())
        .select(Select::table("customers").columns(["id", "name"]))
        .select(Select::table("v"))
        .build()
        .unwrap();
    // a subquery in FROM cannot see the tables beside it
    assert_eq!(
        kind(
            &policy,
            "select o.id from orders o, (select name from customers where customers.id = o.id) x"
        ),
        ErrorKind::Denied
    );
    // a CTE shadows a table of the same name, and is not checked against that table's rule
    assert_eq!(
        rewrite(
            &policy,
            "with secrets as (select id from orders) select id from secrets"
        ),
        "WITH secrets AS (SELECT orders.id FROM orders) SELECT secrets.id FROM secrets"
    );
    assert_eq!(
        kind(&policy, "with x as (select id from orders) select product from x"),
        ErrorKind::Denied
    );
    assert_eq!(
        kind(&policy, "with x as (select 1), x as (select 2) select 1"),
        ErrorKind::Denied
    );
    // a CTE is not visible before it is defined, or outside its query
    assert_eq!(
        kind(&policy, "with a as (select * from b), b as (select 1 as n) select 1"),
        ErrorKind::Denied
    );
    assert_eq!(
        kind(
            &policy,
            "select (with c as (select id from orders) select count(*) from c), id from c"
        ),
        ErrorKind::Denied
    );
    // an unqualified name goes to the one table that lists it, even beside a view that might have it too
    assert_eq!(
        rewrite(&policy, "select qty, v.other from orders join v on v.id = orders.id"),
        "SELECT orders.qty, v.other FROM orders INNER JOIN v ON v.id = orders.id"
    );
    // ... and to the view when nothing lists it
    assert_eq!(
        rewrite(&policy, "select other from orders join v on v.id = orders.id"),
        "SELECT v.other FROM orders INNER JOIN v ON v.id = orders.id"
    );
    // correlated subqueries resolve outwards
    assert_eq!(
        rewrite(
            &policy,
            "select name from customers c where exists (select 1 from orders where id = c.id and name = 'x')"
        ),
        "SELECT c.name FROM customers AS c WHERE EXISTS (SELECT 1 FROM orders WHERE orders.id = c.id AND c.name = 'x')"
    );
    // an alias hides the table name
    assert_eq!(kind(&policy, "select orders.id from orders o"), ErrorKind::Denied);
    // unnamed outputs of a subquery cannot be referenced
    assert_eq!(
        kind(&policy, "select x.count from (select count(*) from orders) x"),
        ErrorKind::Denied
    );
}

#[test]
fn mappers() {
    let policy: Policy<Tenant> = dense()
        .select(Select::table("events").columns(["id", "kind", "at"]))
        .select(Select::table("other").columns(["id"]))
        .insert(Insert::table("events").columns(["kind"]))
        .update(Update::table("events").columns(["kind"]))
        .delete(Delete::table("events"))
        .map_table(|mut table, tenant: &Tenant| {
            if table.name.as_str() == "events" {
                table.schema = Some(Ident::new(tenant.schema)?);
                table.name = Ident::new(format!("events_{}", tenant.id))?;
            }
            Ok(table)
        })
        .map_function(|function, _| {
            Ok(if function.name.as_str() == "now" {
                Expr::Function(Function {
                    schema: Some(Ident::new("app")?),
                    name: Ident::new("frozen_now")?,
                    ..function
                })
            } else {
                Expr::Function(function)
            })
        })
        .map_literal(|literal, _| {
            Ok(match literal {
                Literal::String(s) if s == "secret" => Expr::Literal(Literal::Null),
                other => Expr::Literal(other),
            })
        })
        .map_column(|column, _| {
            Ok(if column.name.as_str() == "at" {
                Expr::Function(Function::call(
                    Ident::new("date_trunc")?,
                    vec!["day".into(), Expr::Column(column)],
                ))
            } else {
                Expr::Column(column)
            })
        })
        .build()
        .unwrap();
    let tenant = Tenant {
        id: 42,
        schema: "tenants",
    };
    let rewrite = |sql: &str| policy.rewrite(sql, &tenant).unwrap_or_else(|e| panic!("{sql}: {e}"));

    let safe = rewrite("select id, at from events where kind = 'secret' and at < now()");
    assert_eq!(
        safe.sql,
        "SELECT events.id, date_trunc('day', events.at) FROM tenants.events_42 AS events WHERE events.kind = NULL AND date_trunc('day', events.at) < app.frozen_now()"
    );
    // the result reports the tables the statement named, not what they were mapped to
    assert_eq!(safe.tables, ["events"]);

    assert_eq!(
        rewrite("select e.id from events e join other on other.id = e.id").sql,
        "SELECT e.id FROM tenants.events_42 AS e INNER JOIN other ON other.id = e.id"
    );
    assert_eq!(
        rewrite("insert into events (kind) values ('a') returning id").sql,
        "INSERT INTO tenants.events_42 AS events (kind) VALUES ('a') RETURNING events.id"
    );
    assert_eq!(
        rewrite("update events set kind = 'b' where id = 1").sql,
        "UPDATE tenants.events_42 AS events SET kind = 'b' WHERE events.id = 1"
    );
    assert_eq!(
        rewrite("delete from events where id = 1").sql,
        "DELETE FROM tenants.events_42 AS events WHERE events.id = 1"
    );
    // the mapper's functions were not, and did not need to be, in the allowed set
    assert_eq!(
        policy.rewrite("select app.frozen_now()", &tenant).unwrap_err().kind(),
        ErrorKind::Denied
    );

    // a mapper that builds something unwritable is an error, not bad SQL
    let bad = Tenant {
        id: 1,
        schema: "has\0nul",
    };
    assert!(policy.rewrite("select id from events", &bad).is_err());
    let policy: Policy = dense()
        .select(orders())
        .map_literal(|_, ()| Ok(Expr::Literal(Literal::Number("1; DROP TABLE orders".into()))))
        .map_column(|_, ()| Err(Error::callback("no columns today")))
        .build()
        .unwrap();
    assert_eq!(
        policy.rewrite("select 1", &()).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    let error = policy.rewrite("select id from orders", &()).unwrap_err();
    assert_eq!(
        (error.kind(), error.message()),
        (ErrorKind::Callback, "no columns today")
    );
}

#[test]
fn other_dialects() {
    let mysql: Policy = dense().select(orders()).dialect(Dialect::MySql).build().unwrap();
    // backticks are MySQL's identifier quotes, and backslash is an escape inside its strings
    assert_eq!(
        rewrite(&mysql, r"select `id` from `orders` where product = 'it\'s'"),
        "SELECT orders.id FROM orders WHERE orders.product = 'it''s'"
    );
    let generic: Policy = dense().select(orders()).dialect(Dialect::Generic).build().unwrap();
    assert_eq!(
        rewrite(&generic, "select id from orders"),
        "SELECT orders.id FROM orders"
    );
    for dialect in [
        Dialect::Postgres,
        Dialect::Generic,
        Dialect::Ansi,
        Dialect::MySql,
        Dialect::Sqlite,
    ] {
        let policy: Policy = dense().select(orders()).dialect(dialect).build().unwrap();
        assert!(policy.rewrite("select id from orders; select 1", &()).is_err());
        assert!(policy.rewrite("select secret from orders", &()).is_err());
    }
}

#[test]
fn only() {
    let policy: Policy = dense()
        .select(Select::table("family").columns(["id"]).only(true))
        .update(Update::table("family").only(true))
        .delete(Delete::table("family").only(true))
        .insert(Insert::table("family"))
        .select(orders())
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&policy, "select f.id from family f join orders on orders.id = f.id"),
        r#"SELECT f.id FROM ONLY "family" AS f INNER JOIN orders ON orders.id = f.id"#
    );
    assert_eq!(
        rewrite(&policy, "update family set x = 1 where id = 1"),
        r#"UPDATE ONLY "family" SET x = 1 WHERE "family".id = 1"#
    );
    assert_eq!(
        rewrite(&policy, "delete from family where id = 1"),
        r#"DELETE FROM ONLY "family" WHERE "family".id = 1"#
    );
    // INSERT has no ONLY, a row goes into the table it names
    assert_eq!(
        rewrite(&policy, "insert into family (id) values (1) returning id"),
        r#"INSERT INTO "family" (id) VALUES (1) RETURNING "family".id"#
    );
    // the statement can ask for ONLY on a table the policy does not mark, in either spelling
    assert_eq!(
        rewrite(&policy, "select id from only orders"),
        "SELECT orders.id FROM ONLY orders"
    );
    assert_eq!(
        rewrite(&policy, "select id from only (orders)"),
        "SELECT orders.id FROM ONLY orders"
    );
    assert_eq!(kind(&policy, "select id from orders *"), ErrorKind::Unsupported);
    assert_eq!(
        kind(&policy, "with c as (select id from orders) select id from only c"),
        ErrorKind::Denied
    );

    // `only` belongs to the table, so the rules for a table have to agree on it
    let message = config_error(
        dense::<()>()
            .select(Select::table("t").only(true))
            .update(Update::table("t"))
            .build(),
    );
    assert_eq!(message, "the rules for table \"t\" disagree about `only`");
    config_error(
        dense::<()>()
            .select(Select::table("t"))
            .select(Select::table("t").only(true))
            .build(),
    );
    config_error(
        dense::<()>()
            .delete(Delete::table("s.t").only(true))
            .select(Select::table("s.t"))
            .build(),
    );
    // an insert rule has no `only`, and a table of the same name in another schema is another table
    assert!(
        dense::<()>()
            .select(Select::table("t").only(true))
            .insert(Insert::table("t"))
            .select(Select::table("s.t"))
            .build()
            .is_ok()
    );
}

#[test]
fn default_schema() {
    let policy: Policy = dense()
        .select(orders())
        .select(Select::table("app.events").columns(["id"]))
        .insert(Insert::table("orders"))
        .update(Update::table("orders"))
        .delete(Delete::table("public.orders"))
        .default_schema("public")
        .build()
        .unwrap();
    // an unqualified name, in a rule or a statement, means the table in the default schema
    let safe = policy.rewrite("select id from orders", &()).unwrap();
    assert_eq!(safe.sql, "SELECT orders.id FROM public.orders");
    assert_eq!(safe.tables, ["public.orders"]);
    assert_eq!(rewrite(&policy, "select id from public.orders"), safe.sql);
    assert_eq!(
        rewrite(&policy, "select o.id from orders o join app.events e on e.id = o.id"),
        "SELECT o.id FROM public.orders AS o INNER JOIN app.events AS e ON e.id = o.id"
    );
    assert_eq!(
        rewrite(&policy, "insert into orders (qty) values (1) returning id"),
        "INSERT INTO public.orders (qty) VALUES (1) RETURNING orders.id"
    );
    assert_eq!(
        rewrite(&policy, "update orders set qty = 1 where id = 1"),
        "UPDATE public.orders SET qty = 1 WHERE orders.id = 1"
    );
    assert_eq!(
        rewrite(&policy, "delete from orders where id = 1"),
        "DELETE FROM public.orders WHERE orders.id = 1"
    );
    // other schemas still have to be named, and a CTE is not a table in any schema
    assert_eq!(kind(&policy, "select id from events"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select id from other.orders"), ErrorKind::Denied);
    assert_eq!(
        rewrite(
            &policy,
            "with orders as (select id from app.events) select id from orders"
        ),
        "WITH orders AS (SELECT events.id FROM app.events) SELECT orders.id FROM orders"
    );
    // the output is accepted again unchanged
    assert_eq!(rewrite(&policy, &safe.sql), safe.sql);

    // `orders` and `public.orders` are one table, so their rules must agree about `only`
    config_error(
        dense::<()>()
            .select(Select::table("orders").only(true))
            .delete(Delete::table("public.orders"))
            .default_schema("public")
            .build(),
    );
    config_error(dense::<()>().default_schema("").build());

    // without it the name is written as the statement gave it
    let plain: Policy = dense().select(orders()).build().unwrap();
    assert_eq!(rewrite(&plain, "select id from orders"), "SELECT orders.id FROM orders");
    assert_eq!(kind(&plain, "select id from public.orders"), ErrorKind::Denied);
}

#[test]
fn grants() {
    let policy: Policy<Tenant> = dense()
        .select(Select::table("orders").columns(["id", "qty"]))
        .select(Select::table("orders").columns(["id", "product"]))
        .select(Select::table("v"))
        .select(Select::table("app.events").columns(["id"]))
        .select(Select::table("we\"ird").columns(["a b"]))
        .insert(
            Insert::table("orders")
                .columns(["product", "qty"])
                .extra(|tenant: &Tenant| [("tenant_id", tenant.id)]),
        )
        .insert(Insert::table("audit"))
        .update(Update::table("orders").columns(["qty"]))
        .update(Update::table("app.events"))
        .delete(Delete::table("orders"))
        .delete(Delete::table("only_delete"))
        .build()
        .unwrap();
    let tenant = Tenant { id: 1, schema: "" };
    assert_eq!(
        policy.grants("app_role", &tenant).unwrap(),
        [
            r#"GRANT USAGE ON SCHEMA "app" TO "app_role""#,
            r#"GRANT INSERT ON "audit" TO "app_role""#,
            r#"GRANT DELETE ON "only_delete" TO "app_role""#,
            // the columns of the two select rules are combined: a grant cannot say "one or the other"
            r#"GRANT SELECT ("id", "qty", "product") ON "orders" TO "app_role""#,
            r#"GRANT INSERT ("product", "qty", "tenant_id") ON "orders" TO "app_role""#,
            r#"GRANT UPDATE ("qty") ON "orders" TO "app_role""#,
            r#"GRANT DELETE ON "orders" TO "app_role""#,
            r#"GRANT SELECT ON "v" TO "app_role""#,
            r#"GRANT SELECT ("a b") ON "we""ird" TO "app_role""#,
            r#"GRANT SELECT ("id") ON "app"."events" TO "app_role""#,
            r#"GRANT UPDATE ON "app"."events" TO "app_role""#,
        ]
    );
    assert_eq!(
        policy.grants("Odd \"Role\"", &tenant).unwrap()[0],
        r#"GRANT USAGE ON SCHEMA "app" TO "Odd ""Role""""#
    );
    assert_eq!(policy.grants("", &tenant).unwrap_err().kind(), ErrorKind::Config);

    // tables are named as the policy resolves them
    let qualified: Policy = dense().select(orders()).default_schema("public").build().unwrap();
    assert_eq!(
        qualified.grants("r", &()).unwrap(),
        [
            r#"GRANT USAGE ON SCHEMA "public" TO "r""#,
            r#"GRANT SELECT ("id", "product", "qty") ON "public"."orders" TO "r""#,
        ]
    );
    let empty: Policy = dense().build().unwrap();
    assert_eq!(empty.grants("r", &()).unwrap(), Vec::<String>::new());

    // a failing `extra` fails the call rather than leaving a column out
    let failing: Policy = dense()
        .insert(Insert::table("t").try_extra(|()| Err(Error::callback("no context"))))
        .build()
        .unwrap();
    assert_eq!(failing.grants("r", &()).unwrap_err().kind(), ErrorKind::Callback);
}

#[test]
fn keyword_forms() {
    let policy: Policy = dense().select(orders()).build().unwrap();
    assert_eq!(
        rewrite(
            &policy,
            "select COALESCE(qty), coalesce(qty, 1, 2), nullif(qty, 0), greatest(1), least(qty, id), current_date, \
             CURRENT_TIMESTAMP, trim(product), trim(leading 'x' from product), trim(trailing from product) from orders"
        ),
        "SELECT COALESCE(orders.qty), COALESCE(orders.qty, 1, 2), NULLIF(orders.qty, 0), GREATEST(1), LEAST(orders.qty, orders.id), CURRENT_DATE, CURRENT_TIMESTAMP, TRIM(BOTH FROM orders.product), TRIM(LEADING 'x' FROM orders.product), TRIM(TRAILING FROM orders.product) FROM orders"
    );
    // and each form reads back as itself
    let all = "select coalesce(qty, 1), nullif(qty, 0), greatest(1), least(qty, id), current_date, current_timestamp, \
               trim(product), trim(leading 'x' from product), trim(trailing from product), trim(both 'x' from product) \
               from orders";
    let once = rewrite(&policy, all);
    assert_eq!(rewrite(&policy, &once), once);
    // without parentheses the name is a column, which no rule allows
    assert_eq!(kind(&policy, "select coalesce from orders"), ErrorKind::Denied);

    for sql in [
        "select coalesce() from orders",
        "select nullif(qty) from orders",
        "select nullif(qty, 1, 2) from orders",
        "select coalesce(distinct qty) from orders",
        "select greatest(qty order by id) from orders",
        "select least(*) from orders",
        "select nullif(qty, 1) filter (where id > 1) from orders",
        "select coalesce(qty) over () from orders",
        "select current_date() from orders",
        "select count(distinct *) from orders",
    ] {
        assert_eq!(kind(&policy, sql), ErrorKind::Unsupported, "{sql}");
    }
    // a qualified name is a call to a function in that schema, not the keyword form
    assert_eq!(kind(&policy, "select app.coalesce(qty) from orders"), ErrorKind::Denied);

    // each is allowed and denied under its own name
    for (name, sql) in [
        ("coalesce", "select coalesce(qty, 1) from orders"),
        ("greatest", "select greatest(qty, 1) from orders"),
        ("least", "select least(qty, 1) from orders"),
        ("nullif", "select nullif(qty, 1) from orders"),
        ("current_date", "select current_date"),
        ("current_timestamp", "select current_timestamp"),
        ("trim", "select trim(product) from orders"),
        ("extract", "select extract(year from current_date)"),
    ] {
        let denied: Policy = dense().select(orders()).deny_functions([name]).build().unwrap();
        let error = denied.rewrite(sql, &()).unwrap_err();
        assert_eq!(error.message(), format!("function {name:?} is not allowed"));
        assert!(policy.rewrite(sql, &()).is_ok(), "{sql}");
    }
}

#[test]
fn order_and_group_keys() {
    use p14g::ast::{Expr, Literal};

    let policy: Policy = dense().select(orders()).build().unwrap();
    // a bare integer is a position; any other bare constant is a syntax error in Postgres
    assert_eq!(
        rewrite(&policy, "select id, qty from orders group by 1, 2 order by 2 desc, id"),
        "SELECT orders.id, orders.qty FROM orders GROUP BY 1, 2 ORDER BY 2 DESC, orders.id"
    );
    for sql in [
        "select id from orders order by 'x'",
        "select id from orders order by null",
        "select id from orders order by true",
        "select count(*) from orders group by 'x'",
    ] {
        let error = policy.rewrite(sql, &()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{sql}");
        assert!(
            error
                .message()
                .starts_with("a constant that is not a column position in"),
            "{error}"
        );
    }
    // inside an expression, an aggregate or a window, a constant is a value like any other
    assert_eq!(
        rewrite(
            &policy,
            "select count(*) over (order by 1, 'x') from orders order by id + 1, 'x' || product"
        ),
        "SELECT count(*) OVER (ORDER BY 1, 'x') FROM orders ORDER BY orders.id + 1, 'x' || orders.product"
    );

    // a mapper cannot put a constant there either, and a position is not a literal for a mapper to change
    let mapped: Policy = dense()
        .select(orders())
        .map_column(|column, ()| {
            Ok(if column.name.as_str() == "qty" {
                Expr::Literal(Literal::Number("7".into()))
            } else {
                Expr::Column(column)
            })
        })
        .map_literal(|_, ()| Ok(Expr::Literal(Literal::Number("9".into()))))
        .build()
        .unwrap();
    assert_eq!(
        kind(&mapped, "select id from orders order by qty"),
        ErrorKind::Unsupported
    );
    assert_eq!(
        kind(&mapped, "select count(*) from orders group by qty"),
        ErrorKind::Unsupported
    );
    assert_eq!(
        rewrite(&mapped, "select id, 5 from orders order by 1, qty + 1"),
        "SELECT orders.id, 9 FROM orders ORDER BY 1, 9 + 9"
    );
}

#[test]
fn quote_identifiers() {
    let build = |quote| -> Policy {
        dense()
            .select(Select::table("orders"))
            .select(Select::table("user"))
            .select(Select::table("app.Events"))
            .quote_identifiers(quote)
            .build()
            .unwrap()
    };
    let minimal = build(QuoteIdentifiers::Minimal);
    let always = build(QuoteIdentifiers::Always);
    let sql = r#"select id, "user", "Mixed", "with space", "1x", _x1, name as "select", 1 as plain from orders o"#;
    // quoted only if the spelling needs it, or if it is a keyword and not after a dot
    assert_eq!(
        rewrite(&minimal, sql),
        r#"SELECT o.id, o.user, o."Mixed", o."with space", o."1x", o._x1, o.name AS "select", 1 AS plain FROM orders AS o"#
    );
    assert_eq!(
        rewrite(&always, sql),
        r#"SELECT "o"."id", "o"."user", "o"."Mixed", "o"."with space", "o"."1x", "o"."_x1", "o"."name" AS "select", 1 AS "plain" FROM "orders" AS "o""#
    );
    // unquoted, `user` is the current role and `current_date` a function
    assert_eq!(
        rewrite(
            &minimal,
            r#"select id, 1 as "current_date" from "user" order by "current_date""#
        ),
        r#"SELECT "user".id, 1 AS "current_date" FROM "user" ORDER BY "current_date""#
    );
    assert_eq!(
        rewrite(&minimal, r#"select e.id from app."Events" e"#),
        r#"SELECT e.id FROM app."Events" AS e"#
    );
    assert_eq!(
        rewrite(
            &minimal,
            "select lower(product), left(product, 1), position('a' in product) from orders"
        ),
        r#"SELECT lower(orders.product), left(orders.product, 1), "position"(orders.product, 'a') FROM orders"#
    );
    // both forms read back as themselves
    for policy in [&minimal, &always] {
        let once = rewrite(policy, sql);
        assert_eq!(rewrite(policy, &once), once);
    }
    assert_eq!(QuoteIdentifiers::parse("ALWAYS").unwrap(), QuoteIdentifiers::Always);
    assert_eq!(QuoteIdentifiers::parse("never").unwrap_err().kind(), ErrorKind::Config);
    // grants are run once by hand, and are always quoted
    assert_eq!(
        minimal.grants("r", &()).unwrap()[1],
        r#"GRANT SELECT ON "orders" TO "r""#
    );
}

#[test]
fn layout() {
    let policy: Policy = Policy::builder()
        .select(orders())
        .select(Select::table("customers"))
        .insert(Insert::table("orders"))
        .update(Update::table("orders"))
        .delete(Delete::table("orders"))
        .build()
        .unwrap();
    let sql = "with big as (select id from orders where qty > 1) \
               select o.id, c.name, count(*) from orders o join customers c on c.id = o.id, customers x \
               where o.qty > 1 and o.id in (select id from big) group by o.id, c.name having count(*) > 1 \
               order by o.id desc limit 10 offset 5";
    // each clause of the statement on its own line, and subqueries on one
    let multiline = "WITH big AS (SELECT orders.id FROM orders WHERE orders.qty > 1)
SELECT o.id, c.name, count(*)
FROM orders AS o
INNER JOIN customers AS c ON c.id = o.id, customers AS x
WHERE o.qty > 1 AND o.id IN (SELECT big.id FROM big)
GROUP BY o.id, c.name
HAVING count(*) > 1
ORDER BY o.id DESC
LIMIT 10
OFFSET 5";
    assert_eq!(rewrite(&policy, sql), multiline);
    assert_eq!(
        rewrite(
            &policy,
            "select id from orders union all (select id from customers limit 1) order by 1"
        ),
        "(SELECT orders.id FROM orders)\nUNION ALL\n(SELECT customers.id FROM customers LIMIT 1)\nORDER BY 1"
    );
    assert_eq!(
        rewrite(&policy, "insert into orders (qty) values (1), (2) returning id"),
        "INSERT INTO orders (qty)\nVALUES (1), (2)\nRETURNING orders.id"
    );
    assert_eq!(
        rewrite(&policy, "update orders set qty = 1 where id = 1 returning *"),
        "UPDATE orders\nSET qty = 1\nWHERE orders.id = 1\nRETURNING orders.id, orders.product, orders.qty"
    );
    assert_eq!(
        rewrite(&policy, "delete from orders where id = 1"),
        "DELETE FROM orders\nWHERE orders.id = 1"
    );
    assert_eq!(rewrite(&policy, "select 1"), "SELECT 1");

    // the two layouts differ only in whitespace, and each reads back as itself
    let dense: Policy = dense()
        .select(orders())
        .select(Select::table("customers"))
        .build()
        .unwrap();
    assert_eq!(rewrite(&dense, sql), multiline.replace('\n', " "));
    assert_eq!(rewrite(&policy, multiline), multiline);
    assert_eq!(Layout::parse("Dense").unwrap(), Layout::Dense);
    assert_eq!(Layout::parse("wide").unwrap_err().kind(), ErrorKind::Config);
}

#[test]
fn parentheses() {
    let policy: Policy = dense().select(Select::table("t")).build().unwrap();
    let where_ = |condition: &str| {
        let sql = rewrite(&policy, &format!("select a from t where {condition}"));
        // however the input was grouped, the output reads back as itself
        assert_eq!(rewrite(&policy, &sql), sql, "{condition}");
        sql.strip_prefix("SELECT t.a FROM t WHERE ").unwrap().to_owned()
    };
    // a condition with the clause to itself has none, nor does a chain of AND or of OR
    assert_eq!(where_("a = 1"), "t.a = 1");
    assert_eq!(where_("((a = 1))"), "t.a = 1");
    assert_eq!(where_("a = 1 and b = 2 and c = 3"), "t.a = 1 AND t.b = 2 AND t.c = 3");
    assert_eq!(where_("a = 1 and (b = 2 and c = 3)"), "t.a = 1 AND t.b = 2 AND t.c = 3");
    assert_eq!(where_("a = 1 or b = 2 or c = 3"), "t.a = 1 OR t.b = 2 OR t.c = 3");
    // mixing AND and OR keeps them, whichever way the input grouped it
    assert_eq!(where_("a = 1 or b = 2 and c = 3"), "t.a = 1 OR (t.b = 2 AND t.c = 3)");
    assert_eq!(where_("(a = 1 or b = 2) and c = 3"), "(t.a = 1 OR t.b = 2) AND t.c = 3");
    assert_eq!(
        where_("a = 1 and (b = 2 or c = 3) and d = 4"),
        "t.a = 1 AND (t.b = 2 OR t.c = 3) AND t.d = 4"
    );
    // comparisons and tests stand bare beside AND and OR
    assert_eq!(
        where_("a is null and b in (1, 2) and c like 'x' and d <> 1 and exists (select 1) and a in (select 1)"),
        "t.a IS NULL AND t.b IN (1, 2) AND t.c LIKE 'x' AND t.d <> 1 AND EXISTS (SELECT 1) AND t.a IN (SELECT 1)"
    );
    // everything else beside them is wrapped
    assert_eq!(
        where_("not a = 1 and b between 1 and 2 and not exists (select 1) and a is distinct from b and c"),
        "(NOT (t.a = 1)) AND (t.b BETWEEN 1 AND 2) AND (NOT EXISTS (SELECT 1)) AND (t.a IS DISTINCT FROM t.b) AND t.c"
    );
    // and the operands of every other operator always are, so precedence is never in question
    assert_eq!(
        where_("a + b * c > (a - b) - c"),
        "(t.a + (t.b * t.c)) > ((t.a - t.b) - t.c)"
    );
    assert_eq!(where_("a = -1 and - a = b"), "t.a = (- 1) AND (- t.a) = t.b");
    assert_eq!(where_("(a = b) = (c < d)"), "(t.a = t.b) = (t.c < t.d)");
    assert_eq!(where_("(a and b) is true"), "(t.a AND t.b) IS TRUE");
    assert_eq!(where_("(a or b) = c"), "(t.a OR t.b) = t.c");
    assert_eq!(
        where_("a between b + 1 and c or d"),
        "(t.a BETWEEN (t.b + 1) AND t.c) OR t.d"
    );
    // each select item, function argument and list item has its place to itself
    assert_eq!(
        rewrite(
            &policy,
            "select a + 1, -a, a = 1 and b = 2, lower(a || 'x'), case when a > 1 then b + 1 end from t where a in (1 + 1, b)"
        ),
        "SELECT t.a + 1, - t.a, t.a = 1 AND t.b = 2, lower(t.a || 'x'), CASE WHEN t.a > 1 THEN t.b + 1 END FROM t WHERE t.a IN (1 + 1, t.b)"
    );
}

#[test]
fn qualify_builtins() {
    let build = |qualify| -> Policy {
        dense()
            .select(orders())
            .functions(["app.total", "mine"])
            .qualify_builtins(qualify)
            .build()
            .unwrap()
    };
    let sql = "select count(*), lower(product), left(product, 1), replace(product, 'a', 'b'), \
               substring(product from 2), position('a' in product), app.total(id), mine(id), pg_catalog.upper(product) \
               from orders";
    // off: builtins are written by name. A name that is a keyword is quoted, because some keywords are
    // grammar before a `(` (`substring`, `position`), except the builtins known to be fine (`left`, `replace`)
    let plain = build(false);
    assert_eq!(
        rewrite(&plain, sql),
        r#"SELECT count(*), lower(orders.product), left(orders.product, 1), replace(orders.product, 'a', 'b'), "substring"(orders.product, 2), "position"(orders.product, 'a'), app.total(orders.id), mine(orders.id), upper(orders.product) FROM orders"#
    );
    // on: the default functions get their schema, the ones the policy added are written as it named them
    let qualified = build(true);
    assert_eq!(
        rewrite(&qualified, sql),
        "SELECT pg_catalog.count(*), pg_catalog.lower(orders.product), pg_catalog.left(orders.product, 1), pg_catalog.replace(orders.product, 'a', 'b'), pg_catalog.substring(orders.product, 2), pg_catalog.position(orders.product, 'a'), app.total(orders.id), mine(orders.id), pg_catalog.upper(orders.product) FROM orders"
    );
    for policy in [&plain, &qualified] {
        let once = rewrite(policy, sql);
        assert_eq!(rewrite(policy, &once), once);
    }
    // the keyword forms are grammar and have no schema either way
    assert_eq!(
        rewrite(
            &qualified,
            "select coalesce(qty, 0), trim(product), extract(year from current_date) from orders"
        ),
        "SELECT COALESCE(orders.qty, 0), TRIM(BOTH FROM orders.product), EXTRACT(YEAR FROM CURRENT_DATE) FROM orders"
    );
    let always: Policy = dense()
        .select(orders())
        .quote_identifiers(QuoteIdentifiers::Always)
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&always, "select lower(product) from orders"),
        r#"SELECT "lower"("orders"."product") FROM "orders""#
    );
}

#[test]
fn filters() {
    let org = |tenant: &Tenant| Filter::new("org = :org and deleted_at is null").bind("org", tenant.id);
    let policy: Policy<Tenant> = dense()
        .select(
            Select::table("orders")
                .columns(["id", "qty", "customer_id"])
                .filter(org),
        )
        .select(Select::table("customers").filter(|tenant: &Tenant| {
            Filter::new("customers.org = :org and status in (:statuses) and created > :since::timestamptz")
                .bind("org", tenant.id)
                .bind("statuses", vec!["open", "o'k"])
                .bind("since", "2026-01-01")
        }))
        .select(Select::table("plain"))
        .insert(
            Insert::table("orders")
                .columns(["qty"])
                .extra(|tenant: &Tenant| [("org", tenant.id)]),
        )
        .update(Update::table("orders").columns(["qty", "org"]).filter(org))
        .delete(Delete::table("orders").filter(org))
        .build()
        .unwrap();
    let tenant = Tenant { id: 42, schema: "" };
    let rewrite = |sql: &str| {
        policy
            .rewrite(sql, &tenant)
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .sql
    };
    let orders = "(SELECT orders.id, orders.qty, orders.customer_id FROM orders WHERE orders.org = 42 AND orders.deleted_at IS NULL)";

    // a filtered table is read through a subquery that applies the filter, under the name the statement used
    assert_eq!(
        rewrite("select count(*) from orders where qty > 1"),
        format!("SELECT count(*) FROM {orders} AS orders WHERE orders.qty > 1")
    );
    // which holds on either side of an outer join, and for a rule with all columns keeps `*`
    assert_eq!(
        rewrite("select o.*, c.name from orders o left join customers c on c.id = o.customer_id"),
        format!(
            "SELECT o.id, o.qty, o.customer_id, c.name FROM {orders} AS o LEFT JOIN (SELECT * FROM customers WHERE \
             customers.org = 42 AND customers.status IN ('open', 'o''k') AND customers.created > CAST('2026-01-01' AS \
             timestamp with time zone)) AS c ON c.id = o.customer_id"
        )
    );
    // every use of the table is filtered: a self-join, a subquery, a CTE
    assert_eq!(
        rewrite("select a.id from orders a join orders b on b.id = a.id where a.id in (select id from orders)"),
        format!(
            "SELECT a.id FROM {orders} AS a INNER JOIN {orders} AS b ON b.id = a.id WHERE a.id IN (SELECT orders.id \
             FROM {orders} AS orders)"
        )
    );
    assert_eq!(
        rewrite("with o as (select id from orders) select o.id, plain.x from o, plain"),
        format!("WITH o AS (SELECT orders.id FROM {orders} AS orders) SELECT o.id, plain.x FROM o, plain")
    );
    // each filter goes on its own table when the FROM list mixes CTEs, derived tables and joins
    assert_eq!(
        rewrite(
            "with p as (select x from plain) select 1 from p, (select id from orders) d join plain on true, \
             plain p2 join orders o on o.id = d.id"
        ),
        format!(
            "WITH p AS (SELECT plain.x FROM plain) SELECT 1 FROM p, (SELECT orders.id FROM {orders} AS orders) AS d \
             INNER JOIN plain ON TRUE, plain AS p2 INNER JOIN {orders} AS o ON o.id = d.id"
        )
    );
    // the columns the filter reads are not thereby readable by the statement
    assert_eq!(
        policy.rewrite("select org from orders", &tenant).unwrap_err().kind(),
        ErrorKind::Denied
    );
    assert_eq!(
        policy
            .rewrite("select id from orders where org = 1", &tenant)
            .unwrap_err()
            .kind(),
        ErrorKind::Denied
    );

    // a write takes the filter as part of its WHERE, ahead of the statement's own condition
    assert_eq!(
        rewrite("update orders set qty = qty + 1 where id = 7 or true returning *"),
        "UPDATE orders SET qty = orders.qty + 1 WHERE orders.org = 42 AND orders.deleted_at IS NULL AND (orders.id = 7 \
         OR TRUE) RETURNING orders.id, orders.qty, orders.customer_id"
    );
    assert_eq!(
        rewrite("delete from orders as o where o.id = 7"),
        "DELETE FROM orders AS o WHERE o.org = 42 AND o.deleted_at IS NULL AND o.id = 7"
    );
    // a subquery in the WHERE of a write is a read like any other
    assert_eq!(
        rewrite("delete from orders where id in (select customer_id from orders o2)"),
        format!(
            "DELETE FROM orders WHERE orders.org = 42 AND orders.deleted_at IS NULL AND orders.id IN (SELECT \
             o2.customer_id FROM {orders} AS o2)"
        )
    );
    // a column the filter reads cannot be set, even though the rule lists it
    let error = policy
        .rewrite("update orders set org = 1 where id = 7", &tenant)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Denied);
    assert_eq!(
        error.message(),
        "column \"org\" of table \"orders\" is used by the policy's filter and cannot be set"
    );
    // the guard against a write with no WHERE still asks the statement for one
    assert_eq!(
        policy.rewrite("delete from orders", &tenant).unwrap_err().kind(),
        ErrorKind::Denied
    );
    // an insert has no rows to filter, its columns come from `extra`
    assert_eq!(
        rewrite("insert into orders (qty) values (1)"),
        "INSERT INTO orders (qty, org) VALUES (1, 42)"
    );

    // the filter's columns are in the grants, since Postgres checks them like any other read
    assert_eq!(
        policy.grants("app", &tenant).unwrap(),
        [
            r#"GRANT SELECT ON "customers" TO "app""#,
            r#"GRANT SELECT ("id", "qty", "customer_id", "deleted_at", "org") ON "orders" TO "app""#,
            r#"GRANT INSERT ("qty", "org") ON "orders" TO "app""#,
            r#"GRANT UPDATE ("qty", "org") ON "orders" TO "app""#,
            r#"GRANT DELETE ON "orders" TO "app""#,
            r#"GRANT SELECT ON "plain" TO "app""#,
        ]
    );
}

type MakeFilter = fn(&()) -> Filter;

#[test]
fn filter_values_and_errors() {
    let build = |filter: fn(&()) -> Filter| -> Policy {
        dense()
            .select(Select::table("t").filter(filter))
            .update(Update::table("t").allow_unfiltered(true))
            .delete(Delete::table("t").allow_unfiltered(true).filter(filter))
            .build()
            .unwrap()
    };
    let where_ = |filter: fn(&()) -> Filter| {
        let sql = rewrite(&build(filter), "select a from t");
        sql.strip_prefix("SELECT t.a FROM (SELECT * FROM t WHERE ")
            .and_then(|rest| rest.strip_suffix(") AS t"))
            .unwrap_or_else(|| panic!("{sql}"))
            .to_owned()
    };
    // values are literals whatever they contain
    assert_eq!(
        where_(
            |()| Filter::new("a = :s or b = :n or c = :f or d = :t or e is not distinct from :null")
                .bind("s", "x' OR '1'='1")
                .bind("n", -7)
                .bind("f", 1.5)
                .bind("t", true)
                .bind("null", Literal::Null)
        ),
        "t.a = 'x'' OR ''1''=''1' OR t.b = (- 7) OR t.c = 1.5 OR t.d = TRUE OR (t.e IS NOT DISTINCT FROM NULL)"
    );
    assert_eq!(
        where_(|()| Filter::new("a = :s").bind("s", r"back\slash'")),
        r"t.a = E'back\\slash'''"
    );
    // a list is the items of IN, a single value can be one item of it
    assert_eq!(
        where_(|()| Filter::new("a in (:xs) and b not in (:y, 3)")
            .bind("xs", vec![1, 2, 3])
            .bind("y", 2)),
        "t.a IN (1, 2, 3) AND t.b NOT IN (2, 3)"
    );
    // the filter can use what the untrusted statement may not: any function, any operator, a qualified name
    assert_eq!(
        where_(|()| Filter::new("t.a ~ '^x' and pg_has_role(owner, 'member') and lower(b) = c")),
        "(t.a ~ '^x') AND pg_has_role(t.owner, 'member') AND lower(t.b) = t.c"
    );
    assert_eq!(where_(|()| Filter::new("true")), "TRUE");
    // an unused value is ignored, a name is matched exactly
    assert_eq!(
        where_(|()| Filter::new("a = :A").bind("A", 1).bind("a", 2).bind("unused", 3)),
        "t.a = 1"
    );

    // with parameters, the strings a filter binds are parameters too
    let params: Policy = dense()
        .select(Select::table("t").filter(|()| Filter::new("a = :s and b = :n").bind("s", "x").bind("n", 1)))
        .literals(Literals::Params)
        .build()
        .unwrap();
    let safe = params.rewrite("select a from t where c = 'y' and d = $1", &()).unwrap();
    assert_eq!(
        safe.sql,
        "SELECT t.a FROM (SELECT * FROM t WHERE t.a = $2 AND t.b = 1) AS t WHERE t.c = $3 AND t.d = $1"
    );
    assert_eq!(safe.params, ["x", "y"]);

    // a filter that cannot be used rejects the statement, it is never left out
    let cases: [(MakeFilter, &str); 10] = [
        (
            |()| Filter::new("a = :missing"),
            "the filter uses :missing but no value was given for it",
        ),
        (
            |()| Filter::new("a = :xs").bind("xs", vec![1]),
            ":xs is a list, which can only be used as IN (:xs)",
        ),
        (
            |()| Filter::new("a in (:xs)").bind("xs", Vec::<i32>::new()),
            ":xs is an empty list, and IN () is not valid SQL",
        ),
        (
            |()| Filter::new("a = $1"),
            "the placeholder \"$1\" is not supported in a filter (use :name)",
        ),
        (
            |()| Filter::new("a = :1").bind("1", 1),
            "the placeholder \":1\" is not supported in a filter (use :name)",
        ),
        (
            |()| Filter::new("a in (select id from other)"),
            "a subquery in a filter is not supported",
        ),
        (|()| Filter::new("other.a = 1"), "other.a is a column of another table"),
        (
            |()| Filter::new("a = 1; drop table t"),
            "expected one expression, found ; after it",
        ),
        (|()| Filter::new("a = 1 or"), "Expected: an expression, found: EOF"),
        (|()| Filter::new(""), "Expected: an expression, found: EOF"),
    ];
    for (filter, message) in cases {
        let policy = build(filter);
        for sql in ["select a from t", "delete from t", "update t set a = 1 where a = 2"] {
            let error = policy.rewrite(sql, &()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Callback, "{sql}: {error}");
            assert_eq!(
                error.message(),
                format!("invalid filter for table \"t\": {message}"),
                "{sql}"
            );
        }
        assert_eq!(policy.grants("r", &()).unwrap_err().kind(), ErrorKind::Callback);
    }
    let failing: Policy = dense()
        .select(Select::table("t").try_filter(|()| Err(Error::callback("no org"))))
        .build()
        .unwrap();
    assert_eq!(failing.rewrite("select a from t", &()).unwrap_err().message(), "no org");

    // two delete rules for one table would be two filters with nothing to choose between them
    config_error(
        dense::<()>()
            .delete(Delete::table("t"))
            .delete(Delete::table("t").allow_unfiltered(true))
            .build(),
    );
}

#[test]
fn filters_and_alternative_rules() {
    // everyone may read the public columns of any row, and all the columns of their own
    let policy: Policy<Tenant> = dense()
        .select(Select::table("docs").columns(["id", "title"]))
        .select(
            Select::table("docs")
                .columns(["id", "title", "body"])
                .filter(|tenant: &Tenant| Filter::new("owner = :owner").bind("owner", tenant.id)),
        )
        .update(Update::table("docs").columns(["title"]))
        .build()
        .unwrap();
    let tenant = Tenant { id: 9, schema: "" };
    let rewrite = |sql: &str| policy.rewrite(sql, &tenant).unwrap().sql;
    assert_eq!(rewrite("select title from docs"), "SELECT docs.title FROM docs");
    assert_eq!(
        rewrite("select title, body from docs"),
        "SELECT docs.title, docs.body FROM (SELECT docs.id, docs.title, docs.body FROM docs WHERE docs.owner = 9) AS docs"
    );
    // a write is held to the filter of the rule its WHERE was read under
    assert_eq!(
        rewrite("update docs set title = 'x' where id = 1"),
        "UPDATE docs SET title = 'x' WHERE docs.id = 1"
    );
    assert_eq!(
        rewrite("update docs set title = 'x' where body like '%secret%'"),
        "UPDATE docs SET title = 'x' WHERE docs.owner = 9 AND docs.body LIKE '%secret%'"
    );
}

/// sqlparser builds chains of operators with a loop, so they can be thousands of levels deep whatever its
/// recursion limit says. These are the deepest trees each kind of chain can make within the default
/// limits, run on a thread with a small stack: nothing may recurse down them unguarded, including drop.
#[test]
fn deep_input_does_not_overflow() {
    fn chain(prefix: &str, repeat: &str, suffix: &str, count: usize) -> String {
        format!("{prefix}{}{suffix}", repeat.repeat(count))
    }

    let limits = Limits {
        max_sql_bytes: 1 << 20,
        max_nodes: 100_000,
        ..Limits::default()
    };
    let cases = [
        chain("select 1", "+1", " from orders", 49_000),
        chain("select id", " or id", " from orders", 49_000),
        chain("select id", "::int", " from orders", 33_000),
        chain("select id", " is null", " from orders", 33_000),
        chain("select id", " like 'a'", " from orders", 33_000),
        chain("select id", " collate x", " from orders", 33_000),
        chain("select id", " at time zone 'x'", " from orders", 20_000),
        chain("select id", "[1]", " from orders", 24_000),
        chain("select id", ".a", " from orders", 49_000),
        chain("select id", " -> 'a'", " from orders", 33_000),
        chain("select id from orders", " union select id from orders", "", 10_000),
        chain("select id from orders", " join orders on true", "", 10_000),
        chain("select id from orders where id = 1", " and id in (1)", "", 15_000),
        chain("select ", "(", "1", 49_000),
        chain("select ", "- ", "1", 49_000),
        chain("select ", "not ", "true", 49_000),
        chain("select ", "(select ", "1", 30_000),
        chain("select ", "case when ", "1", 30_000),
        chain("select ", "f(", "1", 49_000),
        chain("select * from ", "(", "orders", 49_000),
        chain("insert into orders (qty) values (1)", ", (1)", "", 20_000),
    ];
    let thread = thread::Builder::new().stack_size(192 * 1024).spawn(move || {
        let policy: Policy = dense()
            .select(orders())
            .insert(Insert::table("orders"))
            .limits(limits)
            .build()
            .unwrap();
        // empty statements are skipped, so this one is simply `SELECT 1`
        assert_eq!(rewrite(&policy, &chain("select 1", ";", "", 90_000)), "SELECT 1");
        for sql in &cases {
            assert!(sql.len() < 1 << 20);
            let error = policy
                .rewrite(sql, &())
                .expect_err("a pathological statement was accepted");
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::Limit | ErrorKind::Parse | ErrorKind::Unsupported
                ),
                "{}...: {error}",
                &sql[..40]
            );
        }
    });
    thread.unwrap().join().unwrap();
}

/// A mapper can also be a type, which is the way to handle several kinds of node with shared state.
#[test]
fn mapper_trait() {
    struct Prefix(&'static str);

    impl Mapper<()> for Prefix {
        fn map_table(&self, mut table: Table, (): &()) -> Result<Table, Error> {
            table.name = Ident::new(format!("{}{}", self.0, table.name))?;
            Ok(table)
        }

        fn map_literal(&self, literal: Literal, (): &()) -> Result<Expr, Error> {
            Ok(match literal {
                Literal::String(s) => Expr::Literal(Literal::String(format!("{}{s}", self.0))),
                other => Expr::Literal(other),
            })
        }
    }

    let policy: Policy = dense().select(orders()).mapper(Prefix("x_")).build().unwrap();
    assert_eq!(
        rewrite(&policy, "select id from orders where product = 'tea' and qty = 1"),
        "SELECT orders.id FROM x_orders AS orders WHERE orders.product = 'x_tea' AND orders.qty = 1"
    );
}

/// Why p14g writes its own SQL: sqlparser's `Display` turns this one string literal into a `UNION`.
///
/// If this starts failing, sqlparser has changed how it escapes. p14g does not depend on the behaviour
/// either way, but the comment in `lower/mod.rs` and the README should be brought up to date.
#[test]
fn sqlparser_display_is_not_safe_to_emit() {
    use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};

    let input = r"SELECT 'x\'' UNION SELECT password FROM secrets --'";
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, input).unwrap();
    assert_eq!(statements.len(), 1);
    let printed = statements[0].to_string();
    assert_eq!(printed, r"SELECT 'x\' UNION SELECT password FROM secrets --'");
    // Postgres reads that as a string, a UNION and a comment
    let reparsed = pg_query::parse(&printed).unwrap();
    assert_eq!(reparsed.tables(), ["secrets"]);

    // p14g keeps it one literal
    let policy: Policy = dense().build().unwrap();
    let safe = policy.rewrite(input, &()).unwrap();
    assert_eq!(safe.sql, r"SELECT E'x\\'' UNION SELECT password FROM secrets --'");
    assert_eq!(pg_query::parse(&safe.sql).unwrap().tables(), Vec::<String>::new());
}
