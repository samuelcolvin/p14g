-- Statements the test policy accepts. A line starting `=> ` gives the exact SQL the statement above it
-- must become; without one the statement only has to be accepted. Every statement here is also run
-- against Postgres by tests/postgres.rs, as a role with the same access as the policy.

-- basics
select id from orders where qty < 3
=> SELECT orders.id FROM orders WHERE orders.qty < 3

SELECT * FROM orders
=> SELECT orders.id, orders.product, orders.qty, orders.customer_id FROM orders

select o.*, c.name from orders o join customers c on c.id = o.customer_id where c.name like 'a%' order by o.id desc limit 10
=> SELECT o.id, o.product, o.qty, o.customer_id, c.name FROM orders AS o INNER JOIN customers AS c ON c.id = o.customer_id WHERE c.name LIKE 'a%' ORDER BY o.id DESC LIMIT 10

select name, count(*) as n from orders join customers on customers.id = customer_id group by name having count(*) > 1 order by n desc
=> SELECT customers.name, count(*) AS n FROM orders INNER JOIN customers ON customers.id = orders.customer_id GROUP BY customers.name HAVING count(*) > 1 ORDER BY n DESC

select * from v
=> SELECT v.id, v.product, v.qty, v.created, v.data, v.tags, v."a""b", v."MiXed" FROM v

select v.id, lower(v.product) lp from v where qty is not null
=> SELECT v.id, lower(v.product) AS lp FROM v WHERE v.qty IS NOT NULL

select 1
=> SELECT 1

select id from orders /* a comment */ where qty = 1 -- trailing
=> SELECT orders.id FROM orders WHERE orders.qty = 1

select distinct product from orders order by product nulls first
=> SELECT DISTINCT orders.product FROM orders ORDER BY orders.product NULLS FIRST

select id from orders limit 2 offset 1
=> SELECT orders.id FROM orders LIMIT 2 OFFSET 1

select id from orders limit all
=> SELECT orders.id FROM orders

select o1.id from orders o1 join orders o2 on o1.id = o2.id
=> SELECT o1.id FROM orders AS o1 INNER JOIN orders AS o2 ON o1.id = o2.id

select o.id, c.name from orders o left join customers c on c.id = o.customer_id
=> SELECT o.id, c.name FROM orders AS o LEFT JOIN customers AS c ON c.id = o.customer_id

select o.id, c.name from orders o right join customers c on c.id = o.customer_id
=> SELECT o.id, c.name FROM orders AS o RIGHT JOIN customers AS c ON c.id = o.customer_id

select o.id, c.name from orders o full outer join customers c on c.id = o.customer_id
=> SELECT o.id, c.name FROM orders AS o FULL JOIN customers AS c ON c.id = o.customer_id

select o.id, c.name from orders o cross join customers c
=> SELECT o.id, c.name FROM orders AS o CROSS JOIN customers AS c

select orders.id, customers.name from orders, customers where customers.id = orders.customer_id
=> SELECT orders.id, customers.name FROM orders, customers WHERE customers.id = orders.customer_id

select id from app.events
=> SELECT events.id FROM app.events

select e.kind from app.events as e
=> SELECT e.kind FROM app.events AS e

-- identifiers
select "id" from orders
=> SELECT orders.id FROM orders

select ID, Product from ORDERS
=> SELECT orders.id, orders.product FROM orders

select "a""b" from v
=> SELECT v."a""b" FROM v

select "MiXed" from v
=> SELECT v."MiXed" FROM v

select id as "weird ""alias""" from orders
=> SELECT orders.id AS "weird ""alias""" FROM orders

-- literals
select 'it''s', $$dollar 'quoted'$$, $tag$it's $$ here$tag$, E'tab\there \'q\' \\', 'back\slash', '' from orders
=> SELECT 'it''s', 'dollar ''quoted''', 'it''s $$ here', E'tab	here ''q'' \\', E'back\\slash', '' FROM orders

select 'x\'' UNION SELECT password FROM secrets --' from orders
=> SELECT E'x\\'' UNION SELECT password FROM secrets --' FROM orders

select -1, +2, 1.5e3, - -1, 0.5, 10 % 3 from orders
=> SELECT - 1, + 2, 1.5e3, - (- 1), 0.5, 10 % 3 FROM orders

select true, false, null from orders
=> SELECT TRUE, FALSE, NULL FROM orders

select date '2020-01-01', timestamp '2020-01-01 10:00:00', interval '1 day' from orders
=> SELECT CAST('2020-01-01' AS date), CAST('2020-01-01 10:00:00' AS timestamp), CAST('1 day' AS interval) FROM orders

-- expressions
select id from orders where id in (1, 2, 3) and qty not in (4, 5)
=> SELECT orders.id FROM orders WHERE orders.id IN (1, 2, 3) AND orders.qty NOT IN (4, 5)

select id from orders where id in (select customer_id from orders where qty between 1 and 5) and not exists (select 1 from customers where customers.id = orders.customer_id)
=> SELECT orders.id FROM orders WHERE orders.id IN (SELECT orders.customer_id FROM orders WHERE orders.qty BETWEEN 1 AND 5) AND (NOT EXISTS (SELECT 1 FROM customers WHERE customers.id = orders.customer_id))

select id from orders where qty not between 1 and 5 or product ilike 'T%' or product not like 'x!_%' escape '!'
=> SELECT orders.id FROM orders WHERE (orders.qty NOT BETWEEN 1 AND 5) OR orders.product ILIKE 'T%' OR orders.product NOT LIKE 'x!_%' ESCAPE '!'

select id from orders where qty is null or qty is not null or (qty > 1) is true or (qty > 1) is not false
=> SELECT orders.id FROM orders WHERE orders.qty IS NULL OR orders.qty IS NOT NULL OR (orders.qty > 1) IS TRUE OR (orders.qty > 1) IS NOT FALSE

select id from orders where qty is distinct from 3 and qty is not distinct from 2
=> SELECT orders.id FROM orders WHERE (orders.qty IS DISTINCT FROM 3) AND (orders.qty IS NOT DISTINCT FROM 2)

select id from orders where not (qty = 1) and qty <> 2 and qty != 3 and qty >= 0 and qty <= 100
=> SELECT orders.id FROM orders WHERE (NOT (orders.qty = 1)) AND orders.qty <> 2 AND orders.qty <> 3 AND orders.qty >= 0 AND orders.qty <= 100

select product || '-' || product, qty + 1, qty - 1, qty * 2, qty / 2 from orders
=> SELECT (orders.product || '-') || orders.product, orders.qty + 1, orders.qty - 1, orders.qty * 2, orders.qty / 2 FROM orders

select case when qty > 1 then 'many' else 'one' end as label from orders group by label
=> SELECT CASE WHEN orders.qty > 1 THEN 'many' ELSE 'one' END AS "label" FROM orders GROUP BY 1

select case qty when 1 then 'one' when 2 then 'two' end from orders
=> SELECT CASE orders.qty WHEN 1 THEN 'one' WHEN 2 THEN 'two' END FROM orders

select cast(qty as text), qty::bigint, qty::numeric(10, 2), product::varchar(3), '1'::int, '1.5'::float8, 'true'::boolean, now()::date from orders
=> SELECT CAST(orders.qty AS text), CAST(orders.qty AS bigint), CAST(orders.qty AS numeric(10, 2)), CAST(orders.product AS varchar(3)), CAST('1' AS integer), CAST('1.5' AS double precision), CAST('true' AS boolean), CAST(now() AS date) FROM orders

select (select max(qty) from orders) as top, (select count(*) from customers)
=> SELECT (SELECT max(orders.qty) FROM orders) AS top, (SELECT count(*) FROM customers)

select data -> 'k' ->> 'n', data #> '{k}', data #>> '{k,n}' from v where data @> '{"k": {}}' and '{}' <@ data
=> SELECT (v.data -> 'k') ->> 'n', v.data #> '{k}', v.data #>> '{k,n}' FROM v WHERE (v.data @> '{"k": {}}') AND ('{}' <@ v.data)

-- subqueries, CTEs, set operations
with big as (select id, qty from orders where qty > 10) select big.id from big join orders on orders.id = big.id
=> WITH big AS (SELECT orders.id, orders.qty FROM orders WHERE orders.qty > 10) SELECT big.id FROM big INNER JOIN orders ON orders.id = big.id

with a as (select id from orders), b as (select id from a) select * from b
=> WITH a AS (SELECT orders.id FROM orders), b AS (SELECT a.id FROM a) SELECT b.id FROM b

select x.id from (select id from orders) x
=> SELECT x.id FROM (SELECT orders.id FROM orders) AS x

select x.* from (select * from orders) as x where x.qty > 1
=> SELECT x.id, x.product, x.qty, x.customer_id FROM (SELECT orders.id, orders.product, orders.qty, orders.customer_id FROM orders) AS x WHERE x.qty > 1

select id from orders union all select id from customers order by id limit 5
=> (SELECT orders.id FROM orders) UNION ALL (SELECT customers.id FROM customers) ORDER BY id LIMIT 5

select id from orders union select id from customers intersect select id from orders except select id from customers
=> ((SELECT orders.id FROM orders) UNION ((SELECT customers.id FROM customers) INTERSECT (SELECT orders.id FROM orders))) EXCEPT (SELECT customers.id FROM customers)

(select id from orders order by id limit 1) union (select id from customers) order by 1
=> (SELECT orders.id FROM orders ORDER BY orders.id LIMIT 1) UNION (SELECT customers.id FROM customers) ORDER BY 1

-- a whole statement in parentheses: Postgres reads clauses outside them as part of the query inside
(select id from orders limit 3)
=> SELECT orders.id FROM orders LIMIT 3

((select id from orders limit 3)) order by id
=> SELECT orders.id FROM orders ORDER BY orders.id LIMIT 3

(select id from orders limit 3) offset 1
=> SELECT orders.id FROM orders LIMIT 3 OFFSET 1

-- ORDER BY outside the parentheses sees the columns of the SELECT inside them, not only its output
(select id from orders) order by qty
=> SELECT orders.id FROM orders ORDER BY orders.qty

with a as (select id from orders) (select id from a limit 1) order by id
=> WITH a AS (SELECT orders.id FROM orders) SELECT a.id FROM a ORDER BY a.id LIMIT 1

select o.id from orders o where o.qty > (select avg(o2.qty) from orders o2 where o2.customer_id = o.customer_id)
=> SELECT o.id FROM orders AS o WHERE o.qty > (SELECT avg(o2.qty) FROM orders AS o2 WHERE o2.customer_id = o.customer_id)

-- aggregates, windows, ordering
select count(distinct product), sum(qty) filter (where qty > 0) from orders
=> SELECT count(DISTINCT orders.product), sum(orders.qty) FILTER (WHERE orders.qty > 0) FROM orders

select row_number() over (partition by customer_id order by id), sum(qty) over (partition by customer_id) from orders
=> SELECT row_number() OVER (PARTITION BY orders.customer_id ORDER BY orders.id), sum(orders.qty) OVER (PARTITION BY orders.customer_id) FROM orders

select string_agg(product, ',' order by product desc) from orders
=> SELECT string_agg(orders.product, ',' ORDER BY orders.product DESC) FROM orders

select date_trunc('day', created) as created, count(*) from v group by created order by created
=> SELECT date_trunc('day', v.created) AS created, count(*) FROM v GROUP BY v.created ORDER BY created

select customer_id, count(*) from orders group by 1 order by 2 desc, 1
=> SELECT orders.customer_id, count(*) FROM orders GROUP BY 1 ORDER BY 2 DESC, 1

select customer_id, sum(qty) as total from orders group by customer_id order by total desc
=> SELECT orders.customer_id, sum(orders.qty) AS total FROM orders GROUP BY orders.customer_id ORDER BY total DESC

select product from orders order by qty * 2 asc nulls last
=> SELECT orders.product FROM orders ORDER BY orders.qty * 2 ASC NULLS LAST

select count(*) over (order by 'x') from orders order by 'x'::text, 1 + 1
=> SELECT count(*) OVER (ORDER BY 'x') FROM orders ORDER BY CAST('x' AS text), 1 + 1

select string_agg(product, ',' order by 'x') from orders group by 'x'::text
=> SELECT string_agg(orders.product, ',' ORDER BY 'x') FROM orders GROUP BY CAST('x' AS text)

-- placeholders
select id from orders where qty = $1 and product = $2
=> SELECT orders.id FROM orders WHERE orders.qty = $1 AND orders.product = $2

-- rule with a restricted operator list
select a from limited where a = 1 and b = 2
=> SELECT limited.a FROM limited WHERE limited.a = 1 AND limited.b = 2

-- writes
insert into orders (product, qty) values ('tea', 2), ('x', 3) returning id
=> INSERT INTO orders (product, qty, tenant_id) VALUES ('tea', 2, 42), ('x', 3, 42) RETURNING orders.id

insert into orders (product, qty) values ('tea', 2)
=> INSERT INTO orders (product, qty, tenant_id) VALUES ('tea', 2, 42)

insert into orders (product, qty) values ((select name from customers where id = 1), 1)
=> INSERT INTO orders (product, qty, tenant_id) VALUES ((SELECT customers.name FROM customers WHERE customers.id = 1), 1, 42)

insert into audit (message) values ('write-only table')
=> INSERT INTO audit (message, tenant_id) VALUES ('write-only table', 42)

update orders set qty = qty + 1 where id = 1 returning *
=> UPDATE orders SET qty = orders.qty + 1 WHERE orders.id = 1 RETURNING orders.id, orders.product, orders.qty, orders.customer_id

update orders as o set qty = 1 where o.id = 1
=> UPDATE orders AS o SET qty = 1 WHERE o.id = 1

update orders set qty = (select count(*) from customers) where product = 'tea'
=> UPDATE orders SET qty = (SELECT count(*) FROM customers) WHERE orders.product = 'tea'

delete from orders where id = 1
=> DELETE FROM orders WHERE orders.id = 1

delete from orders where id in (select id from customers) returning id, product
=> DELETE FROM orders WHERE orders.id IN (SELECT customers.id FROM customers) RETURNING orders.id, orders.product

-- ONLY, asked for by the statement or added by a rule
select * from only orders
=> SELECT orders.id, orders.product, orders.qty, orders.customer_id FROM ONLY orders

select o.id from only orders as o join only (customers) c on c.id = o.customer_id
=> SELECT o.id FROM ONLY orders AS o INNER JOIN ONLY customers AS c ON c.id = o.customer_id

update only orders set qty = 1 where id = 1
=> UPDATE ONLY orders SET qty = 1 WHERE orders.id = 1

delete from only orders where id = 1
=> DELETE FROM ONLY orders WHERE orders.id = 1

select * from family
=> SELECT "family".id, "family".label FROM ONLY "family"

select f.id from family f where f.id in (select id from only family)
=> SELECT f.id FROM ONLY "family" AS f WHERE f.id IN (SELECT "family".id FROM ONLY "family")

update family set label = 'x' where id = 1 returning *
=> UPDATE ONLY "family" SET "label" = 'x' WHERE "family".id = 1 RETURNING "family".id, "family".label

delete from family where id = 2
=> DELETE FROM ONLY "family" WHERE "family".id = 2

insert into family (id, label) values (9, 'new') returning id
=> INSERT INTO "family" (id, "label") VALUES (9, 'new') RETURNING "family".id

-- writes through an updatable view
insert into cheap_orders (product, qty) values ('gum', 1)
=> INSERT INTO cheap_orders (product, qty) VALUES ('gum', 1)

update cheap_orders set qty = 3 where product = 'tea' returning *
=> UPDATE cheap_orders SET qty = 3 WHERE cheap_orders.product = 'tea' RETURNING cheap_orders.id, cheap_orders.product, cheap_orders.qty

delete from cheap_orders where qty = 0
=> DELETE FROM cheap_orders WHERE cheap_orders.qty = 0

-- every default function

select count(*), count(id), sum(qty), avg(qty), min(qty), max(qty), stddev(qty), variance(qty) from orders
=> SELECT count(*), count(orders.id), sum(orders.qty), avg(orders.qty), min(orders.qty), max(orders.qty), stddev(orders.qty), variance(orders.qty) FROM orders

select bool_and(qty > 0), bool_or(qty > 0), every(qty > 0), string_agg(product, ','), array_agg(qty) from orders
=> SELECT bool_and(orders.qty > 0), bool_or(orders.qty > 0), every(orders.qty > 0), string_agg(orders.product, ','), array_agg(orders.qty) FROM orders

select row_number() over (order by id), rank() over (order by id), dense_rank() over (order by id), ntile(2) over (order by id) from orders
=> SELECT row_number() OVER (ORDER BY orders.id), rank() OVER (ORDER BY orders.id), dense_rank() OVER (ORDER BY orders.id), ntile(2) OVER (ORDER BY orders.id) FROM orders

select lag(qty) over (order by id), lead(qty) over (order by id), first_value(qty) over (order by id), last_value(qty) over (order by id) from orders
=> SELECT lag(orders.qty) OVER (ORDER BY orders.id), lead(orders.qty) OVER (ORDER BY orders.id), first_value(orders.qty) OVER (ORDER BY orders.id), last_value(orders.qty) OVER (ORDER BY orders.id) FROM orders

select coalesce(qty, 0), nullif(qty, 0), greatest(qty, 1), least(qty, 1) from orders
=> SELECT COALESCE(orders.qty, 0), NULLIF(orders.qty, 0), GREATEST(orders.qty, 1), LEAST(orders.qty, 1) FROM orders

select lower(product), upper(product), length(product), char_length(product), initcap(product), reverse(product), md5(product) from orders
=> SELECT lower(orders.product), upper(orders.product), length(orders.product), char_length(orders.product), initcap(orders.product), reverse(orders.product), md5(orders.product) FROM orders

select trim(product), trim(both 'x' from product), trim(leading 'x' from product), trim(trailing 'x' from product), ltrim(product), rtrim(product, 'a'), btrim(product, 'a') from orders
=> SELECT TRIM(BOTH FROM orders.product), TRIM(BOTH 'x' FROM orders.product), TRIM(LEADING 'x' FROM orders.product), TRIM(TRAILING 'x' FROM orders.product), ltrim(orders.product), rtrim(orders.product, 'a'), btrim(orders.product, 'a') FROM orders

select substring(product from 1 for 2), substring(product from 2), substring(product for 2), substring(product, 1, 2), substr(product, 1, 2) from orders
=> SELECT "substring"(orders.product, 1, 2), "substring"(orders.product, 2), "substring"(orders.product, 1, 2), "substring"(orders.product, 1, 2), "substring"(orders.product, 1, 2) FROM orders

select left(product, 2), right(product, 2), position('a' in product), strpos(product, 'a'), replace(product, 'a', 'b') from orders
=> SELECT left(orders.product, 2), right(orders.product, 2), "position"(orders.product, 'a'), strpos(orders.product, 'a'), replace(orders.product, 'a', 'b') FROM orders

select concat(product, 'x', qty), concat_ws('-', product, product), starts_with(product, 't'), split_part(product, 'e', 1) from orders
=> SELECT concat(orders.product, 'x', orders.qty), concat_ws('-', orders.product, orders.product), starts_with(orders.product, 't'), split_part(orders.product, 'e', 1) FROM orders

select abs(qty), round(qty / 2.0), round(qty / 3.0, 2), ceil(qty / 2.0), ceiling(qty / 2.0), floor(qty / 2.0), trunc(qty / 2.0) from orders
=> SELECT abs(orders.qty), round(orders.qty / 2.0), round(orders.qty / 3.0, 2), ceil(orders.qty / 2.0), ceiling(orders.qty / 2.0), floor(orders.qty / 2.0), trunc(orders.qty / 2.0) FROM orders

select mod(qty, 2), power(qty, 2), sqrt(qty), sign(qty), ln(qty + 1), log(qty + 1), exp(1), random() from orders
=> SELECT mod(orders.qty, 2), power(orders.qty, 2), sqrt(orders.qty), sign(orders.qty), ln(orders.qty + 1), log(orders.qty + 1), exp(1), random() FROM orders

select now(), current_date, current_timestamp, date_trunc('month', created), date_part('year', created), extract(year from created), extract(epoch from created), age(created) from v
=> SELECT now(), CURRENT_DATE, CURRENT_TIMESTAMP, date_trunc('month', v.created), date_part('year', v.created), EXTRACT(YEAR FROM v.created), EXTRACT(EPOCH FROM v.created), age(v.created) FROM v

select to_char(created, 'YYYY-MM-DD'), to_date('2020-01-01', 'YYYY-MM-DD'), to_timestamp('2020-01-01', 'YYYY-MM-DD'), make_date(2020, 1, 1) from v
=> SELECT to_char(v.created, 'YYYY-MM-DD'), to_date('2020-01-01', 'YYYY-MM-DD'), to_timestamp('2020-01-01', 'YYYY-MM-DD'), make_date(2020, 1, 1) FROM v

select jsonb_extract_path(data, 'k'), jsonb_extract_path_text(data, 'k', 'n'), jsonb_array_length(data -> 'list'), jsonb_typeof(data) from v
=> SELECT jsonb_extract_path(v.data, 'k'), jsonb_extract_path_text(v.data, 'k', 'n'), jsonb_array_length(v.data -> 'list'), jsonb_typeof(v.data) FROM v

select json_extract_path(data::json, 'k'), json_extract_path_text(data::json, 'k', 'n'), json_array_length(data::json -> 'list'), json_typeof(data::json) from v
=> SELECT json_extract_path(CAST(v.data AS json), 'k'), json_extract_path_text(CAST(v.data AS json), 'k', 'n'), json_array_length(CAST(v.data AS json) -> 'list'), json_typeof(CAST(v.data AS json)) FROM v

select array_length(tags, 1), cardinality(tags), array_position(tags, 'a'), gen_random_uuid() from v
=> SELECT array_length(v.tags, 1), cardinality(v.tags), array_position(v.tags, 'a'), gen_random_uuid() FROM v

select pg_catalog.lower(product), PG_CATALOG.COUNT(*) over () from orders
=> SELECT lower(orders.product), count(*) OVER () FROM orders
