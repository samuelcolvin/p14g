//! Policy options and the public API, beyond what the case files cover.

mod common;

use std::thread;

use pgsafe::{
    Delete, Dialect, Error, ErrorKind, Insert, Limits, Literals, Mapper, Op, Policy, Select, Star, StatementKind,
    Update,
    ast::{Expr, Function, Ident, Literal, Table},
    functions,
};

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
        Policy::builder()
            .select(orders())
            .select(Select::table("v"))
            .star_behaviour(star)
            .build()
            .unwrap()
    };

    let expand = build(Star::Expand);
    assert_eq!(
        rewrite(&expand, "select * from orders"),
        r#"SELECT "orders"."id", "orders"."product", "orders"."qty" FROM "orders""#
    );
    assert_eq!(rewrite(&expand, "select * from v"), r#"SELECT "v".* FROM "v""#);
    assert_eq!(
        rewrite(&expand, "select * from orders o join v on v.id = o.id"),
        r#"SELECT "o"."id", "o"."product", "o"."qty", "v".* FROM "orders" AS "o" INNER JOIN "v" ON ("v"."id" = "o"."id")"#
    );
    assert_eq!(
        rewrite(&expand, "select count(*) from orders"),
        r#"SELECT pg_catalog."count"(*) FROM "orders""#
    );

    let allow = build(Star::Allow);
    assert_eq!(rewrite(&allow, "select * from v"), r#"SELECT * FROM "v""#);
    assert_eq!(rewrite(&allow, "select v.* from v"), r#"SELECT "v".* FROM "v""#);
    assert_eq!(kind(&allow, "select * from orders"), ErrorKind::Denied);
    assert_eq!(
        kind(&allow, "select * from orders o join v on v.id = o.id"),
        ErrorKind::Denied
    );
    assert_eq!(
        rewrite(&allow, "select v.* from orders o join v on v.id = o.id"),
        r#"SELECT "v".* FROM "orders" AS "o" INNER JOIN "v" ON ("v"."id" = "o"."id")"#
    );
    // a subquery that kept its star has columns pgsafe cannot list, and is treated like the view under it
    assert_eq!(
        rewrite(&allow, "select x.anything from (select * from v) x"),
        r#"SELECT "x"."anything" FROM (SELECT * FROM "v") AS "x""#
    );

    let reject = build(Star::Reject);
    assert_eq!(kind(&reject, "select * from v"), ErrorKind::Denied);
    assert_eq!(kind(&reject, "select v.* from v"), ErrorKind::Denied);
    assert_eq!(
        rewrite(&reject, "select count(*) from v"),
        r#"SELECT pg_catalog."count"(*) FROM "v""#
    );
}

#[test]
fn rules_for_one_table_are_alternatives() {
    let policy: Policy = Policy::builder()
        .select(Select::table("t").columns(["a"]).operators([Op::Eq]))
        .select(Select::table("t").columns(["b"]).operators([Op::Lt, Op::Gt]))
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&policy, "select a from t where a = 1"),
        r#"SELECT "t"."a" FROM "t" WHERE ("t"."a" = 1)"#
    );
    assert_eq!(
        rewrite(&policy, "select b from t where b < 1"),
        r#"SELECT "t"."b" FROM "t" WHERE ("t"."b" < 1)"#
    );
    // each half is allowed by a rule, but no one rule allows both
    assert_eq!(kind(&policy, "select a from t where a < 1"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select a, b from t"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select a from t where b > 1"), ErrorKind::Denied);
    // two instances of the table can each use a different rule
    assert!(
        policy
            .rewrite("select t1.a from t t1 where t1.a = (select max(t2.b) from t t2)", &())
            .is_err()
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
        r#"SELECT "t"."b" FROM "t" WHERE ("t"."b" > 1)"#
    );
}

#[test]
fn operators() {
    let policy: Policy = Policy::builder()
        .select(orders())
        .operators([Op::Eq, Op::And])
        .build()
        .unwrap();
    assert!(
        policy
            .rewrite("select id from orders where id = 1 and qty = 2", &())
            .is_ok()
    );
    assert_eq!(
        kind(&policy, "select id from orders where id = 1 or qty = 2"),
        ErrorKind::Denied
    );
    // expressions that touch no table are held to the policy default
    assert_eq!(kind(&policy, "select 1 + 1"), ErrorKind::Denied);
    assert_eq!(
        kind(&policy, "select id from orders limit 1 offset 1 + 1"),
        ErrorKind::Unsupported
    );

    let regex: Policy = Policy::builder()
        .select(orders().operators(Op::ALL.iter().copied()))
        .build()
        .unwrap();
    assert_eq!(
        rewrite(
            &regex,
            "select id from orders where product ~ '^t' and product similar to 't%'"
        ),
        r#"SELECT "orders"."id" FROM "orders" WHERE (("orders"."product" ~ '^t') AND ("orders"."product" SIMILAR TO 't%'))"#
    );

    for op in Op::ALL {
        assert_eq!(Op::parse(op.as_str()).unwrap(), *op);
    }
    assert_eq!(Op::parse("<>").unwrap(), Op::NotEq);
    assert_eq!(Op::parse(" LIKE ").unwrap(), Op::Like);
    assert_eq!(Op::parse("xor").unwrap_err().kind(), ErrorKind::Config);
}

#[test]
fn functions_allow_and_deny() {
    let policy: Policy = Policy::builder()
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
        r#"SELECT "app"."order_total"("orders"."id"), "repeat"("orders"."product", 2), pg_catalog."lower"("orders"."product") FROM "orders""#
    );
    assert_eq!(kind(&policy, "select random()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select now()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select pg_catalog.now()"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select order_total(id) from orders"), ErrorKind::Denied);
    assert_eq!(
        kind(&policy, "select other.order_total(id) from orders"),
        ErrorKind::Denied
    );

    let none: Policy = Policy::builder()
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

    let message = config_error(Policy::<()>::builder().deny_functions(["pg_sleep"]).build());
    assert_eq!(
        message,
        "cannot deny function \"pg_sleep\": it is not an allowed function"
    );
    config_error(
        Policy::<()>::builder()
            .default_functions(false)
            .deny_functions(["count"])
            .build(),
    );
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
    config_error(Policy::<()>::builder().select(Select::table("")).build());
    config_error(Policy::<()>::builder().select(Select::table("a.b.c")).build());
    config_error(
        Policy::<()>::builder()
            .select(Select::table("t").columns(["a", "a"]))
            .build(),
    );
    config_error(Policy::<()>::builder().select(Select::table("t").columns([""])).build());
    config_error(Policy::<()>::builder().select(Select::table("x".repeat(64))).build());
    config_error(Policy::<()>::builder().functions(["a.b.c"]).build());
    config_error(
        Policy::<()>::builder()
            .update(Update::table("t").columns(["a\0"]))
            .build(),
    );
    assert_eq!(Dialect::parse("oracle").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Star::parse("maybe").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Literals::parse("bind").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(StatementKind::parse("merge").unwrap_err().kind(), ErrorKind::Config);
    assert_eq!(Dialect::parse("PostgreSQL").unwrap(), Dialect::Postgres);
}

#[test]
fn rule_names_are_exact() {
    let policy: Policy = Policy::builder()
        .select(Select::table("Orders").columns(["Id"]))
        .build()
        .unwrap();
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
    let build = |limits: Limits| -> Policy { Policy::builder().select(orders()).limits(limits).build().unwrap() };
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

    let rows: Policy = Policy::builder()
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

    config_error(
        Policy::<()>::builder()
            .limits(Limits {
                max_depth: 0,
                ..Limits::default()
            })
            .build(),
    );
}

#[test]
fn max_rows() {
    let policy: Policy = Policy::builder().select(orders()).max_rows(Some(100)).build().unwrap();
    assert_eq!(
        rewrite(&policy, "select id from orders"),
        r#"SELECT "orders"."id" FROM "orders" LIMIT 100"#
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 5"),
        r#"SELECT "orders"."id" FROM "orders" LIMIT 5"#
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 500"),
        r#"SELECT "orders"."id" FROM "orders" LIMIT 100"#
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 99999999999999999999999"),
        r#"SELECT "orders"."id" FROM "orders" LIMIT 100"#
    );
    assert_eq!(
        rewrite(&policy, "select id from orders limit 1.5"),
        r#"SELECT "orders"."id" FROM "orders" LIMIT 100"#
    );
    assert_eq!(
        rewrite(&policy, "select id from orders union select id from orders"),
        r#"(SELECT "orders"."id" FROM "orders") UNION (SELECT "orders"."id" FROM "orders") LIMIT 100"#
    );
    assert_eq!(kind(&policy, "select id from orders limit $1"), ErrorKind::Denied);
}

#[test]
fn params_are_numbered_after_the_input_placeholders() {
    let policy: Policy = Policy::builder()
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
        r#"SELECT "orders"."id" FROM "orders" WHERE ((((("orders"."product" = $3) AND ("orders"."qty" = $2)) AND ("orders"."product" <> $4)) AND ("orders"."id" = $1)) AND ("orders"."qty" > 5))"#
    );
    assert_eq!(safe.params, ["tea", "x'y"]);

    let safe = policy
        .rewrite("select date '2020-01-01', true, null, 1.5 from orders", &())
        .unwrap();
    assert_eq!(safe.sql, r#"SELECT CAST($1 AS date), TRUE, NULL, 1.5 FROM "orders""#);
    assert_eq!(safe.params, ["2020-01-01"]);

    let safe = policy
        .rewrite("insert into orders (product) values ('a'), ('b')", &())
        .unwrap();
    assert_eq!(
        safe.sql,
        r#"INSERT INTO "orders" ("product", "note") VALUES ($1, $2), ($3, $4)"#
    );
    assert_eq!(safe.params, ["a", "from the policy", "b", "from the policy"]);
}

struct Tenant {
    id: i64,
    schema: &'static str,
}

#[test]
fn insert_extra() {
    let policy: Policy<Tenant> = Policy::builder()
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
        r#"INSERT INTO "orders" ("product", "qty", "tenant_id") VALUES ('a', 1, (- 7)), ('b', 2, (- 7)) RETURNING "orders"."id""#
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
        r#"INSERT INTO "notes" ("body", "flag", "ratio", "whole", "big", "small", "label", "nothing", "nan") VALUES ('x', TRUE, (- 1.5), 2.0, 1e300, 1e-7, 'it''s', NULL, CAST('NaN' AS double precision))"#
    );
    let error = policy.rewrite("insert into bad (x) values (1)", &tenant).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Callback);
}

#[test]
fn write_rules() {
    let policy: Policy = Policy::builder()
        .select(Select::table("t").columns(["id", "a"]))
        .insert(Insert::table("t"))
        .update(Update::table("t").columns(["a"]))
        .update(Update::table("t").columns(["b"]).allow_unfiltered(true))
        .delete(Delete::table("t").allow_unfiltered(true))
        .delete(Delete::table("u"))
        .build()
        .unwrap();
    assert_eq!(rewrite(&policy, "update t set b = 1"), r#"UPDATE "t" SET "b" = 1"#);
    // the rule that allows the unfiltered update is not the one that allows this column
    assert_eq!(kind(&policy, "update t set a = 1"), ErrorKind::Denied);
    assert_eq!(
        kind(&policy, "update t set a = 1, b = 2 where id = 1"),
        ErrorKind::Denied
    );
    assert_eq!(rewrite(&policy, "delete from t"), r#"DELETE FROM "t""#);
    // `u` can be deleted from but not read, so a WHERE that names a column is refused
    assert_eq!(kind(&policy, "delete from u"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "delete from u where id = 1"), ErrorKind::Denied);
    assert_eq!(
        rewrite(&policy, "delete from u where true"),
        r#"DELETE FROM "u" WHERE TRUE"#
    );
    assert_eq!(kind(&policy, "delete from u where true returning *"), ErrorKind::Denied);
    assert_eq!(
        rewrite(&policy, "insert into t (anything) values (1)"),
        r#"INSERT INTO "t" ("anything") VALUES (1)"#
    );
    assert_eq!(
        rewrite(&policy, "update t as x set a = x.a + 1 where x.id = 1 returning x.*"),
        r#"UPDATE "t" AS "x" SET "a" = ("x"."a" + 1) WHERE ("x"."id" = 1) RETURNING "x"."id", "x"."a""#
    );
    assert_eq!(kind(&policy, "update t set a = b where id = 1"), ErrorKind::Denied);
}

#[test]
fn group_by_names() {
    let policy: Policy = Policy::builder()
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
        r#"SELECT pg_catalog."lower"("orders"."product") AS "product", pg_catalog."count"(*) FROM "orders" GROUP BY "orders"."product""#
    );
    // no listed column of that name, and no table that could be hiding one: it can only be the alias
    assert_eq!(
        rewrite(&policy, "select lower(product) as p, count(*) from orders group by p"),
        r#"SELECT pg_catalog."lower"("orders"."product") AS "p", pg_catalog."count"(*) FROM "orders" GROUP BY 1"#
    );
    // only all-column tables: either reading is allowed, so leave the choice to Postgres
    assert_eq!(
        rewrite(
            &policy,
            "select lower(v.x) as p, count(*) from v join w on w.id = v.id group by p"
        ),
        r#"SELECT pg_catalog."lower"("v"."x") AS "p", pg_catalog."count"(*) FROM "v" INNER JOIN "w" ON ("w"."id" = "v"."id") GROUP BY "p""#
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
        r#"SELECT pg_catalog."lower"("orders"."product") AS "product" FROM "orders" ORDER BY "product""#
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
    let policy: Policy = Policy::builder()
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
        r#"WITH "secrets" AS (SELECT "orders"."id" FROM "orders") SELECT "secrets"."id" FROM "secrets""#
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
        r#"SELECT "orders"."qty", "v"."other" FROM "orders" INNER JOIN "v" ON ("v"."id" = "orders"."id")"#
    );
    // ... and to the view when nothing lists it
    assert_eq!(
        rewrite(&policy, "select other from orders join v on v.id = orders.id"),
        r#"SELECT "v"."other" FROM "orders" INNER JOIN "v" ON ("v"."id" = "orders"."id")"#
    );
    // correlated subqueries resolve outwards
    assert_eq!(
        rewrite(
            &policy,
            "select name from customers c where exists (select 1 from orders where id = c.id and name = 'x')"
        ),
        r#"SELECT "c"."name" FROM "customers" AS "c" WHERE (EXISTS (SELECT 1 FROM "orders" WHERE (("orders"."id" = "c"."id") AND ("c"."name" = 'x'))))"#
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
    let policy: Policy<Tenant> = Policy::builder()
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
        r#"SELECT "events"."id", pg_catalog."date_trunc"('day', "events"."at") FROM "tenants"."events_42" AS "events" WHERE (("events"."kind" = NULL) AND (pg_catalog."date_trunc"('day', "events"."at") < "app"."frozen_now"()))"#
    );
    // the result reports the tables the statement named, not what they were mapped to
    assert_eq!(safe.tables, ["events"]);

    assert_eq!(
        rewrite("select e.id from events e join other on other.id = e.id").sql,
        r#"SELECT "e"."id" FROM "tenants"."events_42" AS "e" INNER JOIN "other" ON ("other"."id" = "e"."id")"#
    );
    assert_eq!(
        rewrite("insert into events (kind) values ('a') returning id").sql,
        r#"INSERT INTO "tenants"."events_42" AS "events" ("kind") VALUES ('a') RETURNING "events"."id""#
    );
    assert_eq!(
        rewrite("update events set kind = 'b' where id = 1").sql,
        r#"UPDATE "tenants"."events_42" AS "events" SET "kind" = 'b' WHERE ("events"."id" = 1)"#
    );
    assert_eq!(
        rewrite("delete from events where id = 1").sql,
        r#"DELETE FROM "tenants"."events_42" AS "events" WHERE ("events"."id" = 1)"#
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
    let policy: Policy = Policy::builder()
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
    let mysql: Policy = Policy::builder()
        .select(orders())
        .dialect(Dialect::MySql)
        .build()
        .unwrap();
    // backticks are MySQL's identifier quotes, and backslash is an escape inside its strings
    assert_eq!(
        rewrite(&mysql, r"select `id` from `orders` where product = 'it\'s'"),
        r#"SELECT "orders"."id" FROM "orders" WHERE ("orders"."product" = 'it''s')"#
    );
    let generic: Policy = Policy::builder()
        .select(orders())
        .dialect(Dialect::Generic)
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&generic, "select id from orders"),
        r#"SELECT "orders"."id" FROM "orders""#
    );
    for dialect in [
        Dialect::Postgres,
        Dialect::Generic,
        Dialect::Ansi,
        Dialect::MySql,
        Dialect::Sqlite,
    ] {
        let policy: Policy = Policy::builder().select(orders()).dialect(dialect).build().unwrap();
        assert!(policy.rewrite("select id from orders; select 1", &()).is_err());
        assert!(policy.rewrite("select secret from orders", &()).is_err());
    }
}

#[test]
fn only() {
    let policy: Policy = Policy::builder()
        .select(Select::table("family").columns(["id"]).only(true))
        .update(Update::table("family").only(true))
        .delete(Delete::table("family").only(true))
        .insert(Insert::table("family"))
        .select(orders())
        .build()
        .unwrap();
    assert_eq!(
        rewrite(&policy, "select f.id from family f join orders on orders.id = f.id"),
        r#"SELECT "f"."id" FROM ONLY "family" AS "f" INNER JOIN "orders" ON ("orders"."id" = "f"."id")"#
    );
    assert_eq!(
        rewrite(&policy, "update family set x = 1 where id = 1"),
        r#"UPDATE ONLY "family" SET "x" = 1 WHERE ("family"."id" = 1)"#
    );
    assert_eq!(
        rewrite(&policy, "delete from family where id = 1"),
        r#"DELETE FROM ONLY "family" WHERE ("family"."id" = 1)"#
    );
    // INSERT has no ONLY, a row goes into the table it names
    assert_eq!(
        rewrite(&policy, "insert into family (id) values (1) returning id"),
        r#"INSERT INTO "family" ("id") VALUES (1) RETURNING "family"."id""#
    );
    // the statement can ask for ONLY on a table the policy does not mark, in either spelling
    assert_eq!(
        rewrite(&policy, "select id from only orders"),
        r#"SELECT "orders"."id" FROM ONLY "orders""#
    );
    assert_eq!(
        rewrite(&policy, "select id from only (orders)"),
        r#"SELECT "orders"."id" FROM ONLY "orders""#
    );
    assert_eq!(kind(&policy, "select id from orders *"), ErrorKind::Unsupported);
    assert_eq!(
        kind(&policy, "with c as (select id from orders) select id from only c"),
        ErrorKind::Denied
    );

    // `only` belongs to the table, so the rules for a table have to agree on it
    let message = config_error(
        Policy::<()>::builder()
            .select(Select::table("t").only(true))
            .update(Update::table("t"))
            .build(),
    );
    assert_eq!(message, "the rules for table \"t\" disagree about `only`");
    config_error(
        Policy::<()>::builder()
            .select(Select::table("t"))
            .select(Select::table("t").only(true))
            .build(),
    );
    config_error(
        Policy::<()>::builder()
            .delete(Delete::table("s.t").only(true))
            .select(Select::table("s.t"))
            .build(),
    );
    // an insert rule has no `only`, and a table of the same name in another schema is another table
    assert!(
        Policy::<()>::builder()
            .select(Select::table("t").only(true))
            .insert(Insert::table("t"))
            .select(Select::table("s.t"))
            .build()
            .is_ok()
    );
}

#[test]
fn default_schema() {
    let policy: Policy = Policy::builder()
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
    assert_eq!(safe.sql, r#"SELECT "orders"."id" FROM "public"."orders""#);
    assert_eq!(safe.tables, ["public.orders"]);
    assert_eq!(rewrite(&policy, "select id from public.orders"), safe.sql);
    assert_eq!(
        rewrite(&policy, "select o.id from orders o join app.events e on e.id = o.id"),
        r#"SELECT "o"."id" FROM "public"."orders" AS "o" INNER JOIN "app"."events" AS "e" ON ("e"."id" = "o"."id")"#
    );
    assert_eq!(
        rewrite(&policy, "insert into orders (qty) values (1) returning id"),
        r#"INSERT INTO "public"."orders" ("qty") VALUES (1) RETURNING "orders"."id""#
    );
    assert_eq!(
        rewrite(&policy, "update orders set qty = 1 where id = 1"),
        r#"UPDATE "public"."orders" SET "qty" = 1 WHERE ("orders"."id" = 1)"#
    );
    assert_eq!(
        rewrite(&policy, "delete from orders where id = 1"),
        r#"DELETE FROM "public"."orders" WHERE ("orders"."id" = 1)"#
    );
    // other schemas still have to be named, and a CTE is not a table in any schema
    assert_eq!(kind(&policy, "select id from events"), ErrorKind::Denied);
    assert_eq!(kind(&policy, "select id from other.orders"), ErrorKind::Denied);
    assert_eq!(
        rewrite(
            &policy,
            "with orders as (select id from app.events) select id from orders"
        ),
        r#"WITH "orders" AS (SELECT "events"."id" FROM "app"."events") SELECT "orders"."id" FROM "orders""#
    );
    // the output is accepted again unchanged
    assert_eq!(rewrite(&policy, &safe.sql), safe.sql);

    // `orders` and `public.orders` are one table, so their rules must agree about `only`
    config_error(
        Policy::<()>::builder()
            .select(Select::table("orders").only(true))
            .delete(Delete::table("public.orders"))
            .default_schema("public")
            .build(),
    );
    config_error(Policy::<()>::builder().default_schema("").build());

    // without it the name is written as the statement gave it
    let plain: Policy = Policy::builder().select(orders()).build().unwrap();
    assert_eq!(
        rewrite(&plain, "select id from orders"),
        r#"SELECT "orders"."id" FROM "orders""#
    );
    assert_eq!(kind(&plain, "select id from public.orders"), ErrorKind::Denied);
}

#[test]
fn grants() {
    let policy: Policy<Tenant> = Policy::builder()
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
    let qualified: Policy = Policy::builder()
        .select(orders())
        .default_schema("public")
        .build()
        .unwrap();
    assert_eq!(
        qualified.grants("r", &()).unwrap(),
        [
            r#"GRANT USAGE ON SCHEMA "public" TO "r""#,
            r#"GRANT SELECT ("id", "product", "qty") ON "public"."orders" TO "r""#,
        ]
    );
    let empty: Policy = Policy::builder().build().unwrap();
    assert_eq!(empty.grants("r", &()).unwrap(), Vec::<String>::new());

    // a failing `extra` fails the call rather than leaving a column out
    let failing: Policy = Policy::builder()
        .insert(Insert::table("t").try_extra(|()| Err(Error::callback("no context"))))
        .build()
        .unwrap();
    assert_eq!(failing.grants("r", &()).unwrap_err().kind(), ErrorKind::Callback);
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
        let policy: Policy = Policy::builder()
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

    let policy: Policy = Policy::builder().select(orders()).mapper(Prefix("x_")).build().unwrap();
    assert_eq!(
        rewrite(&policy, "select id from orders where product = 'tea' and qty = 1"),
        r#"SELECT "orders"."id" FROM "x_orders" AS "orders" WHERE (("orders"."product" = 'x_tea') AND ("orders"."qty" = 1))"#
    );
}

/// Why pgsafe writes its own SQL: sqlparser's `Display` turns this one string literal into a `UNION`.
///
/// If this starts failing, sqlparser has changed how it escapes. pgsafe does not depend on the behaviour
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

    // pgsafe keeps it one literal
    let policy: Policy = Policy::builder().build().unwrap();
    let safe = policy.rewrite(input, &()).unwrap();
    assert_eq!(safe.sql, r"SELECT E'x\\'' UNION SELECT password FROM secrets --'");
    assert_eq!(pg_query::parse(&safe.sql).unwrap().tables(), Vec::<String>::new());
}
