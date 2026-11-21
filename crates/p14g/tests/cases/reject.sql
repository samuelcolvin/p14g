-- Statements the test policy rejects, one per line: the error kind, a colon, the SQL.

-- not exactly one statement
parse: select id from orders; drop table orders
parse: select id from orders; select 1
parse: 
parse: ;
parse: select from where
parse: select id from orders where product = 'unterminated

-- statements other than select, insert, update, delete
unsupported: drop table orders
unsupported: truncate orders
unsupported: explain select id from orders
unsupported: explain analyze delete from orders where id = 1
unsupported: copy orders to stdout
unsupported: copy orders from program 'cat /etc/passwd'
unsupported: set role postgres
unsupported: set search_path = evil
unsupported: show server_version
unsupported: begin
unsupported: commit
unsupported: create table t (a int)
unsupported: create function f() returns int language sql as 'select 1'
unsupported: grant all on orders to public
unsupported: call some_procedure()
unsupported: prepare p as select 1
unsupported: execute p
unsupported: listen chan
unsupported: notify chan
unsupported: vacuum orders
unsupported: lock table orders
unsupported: merge into orders o using customers c on o.id = c.id when matched then delete
parse: table orders
unsupported: values (1)

-- tables the policy does not name
denied: select * from secrets
denied: select password from secrets
denied: select * from pg_shadow
denied: select * from pg_catalog.pg_class
denied: select * from information_schema.tables
denied: select id from events
denied: select id from public.orders
denied: select id from orders where id in (select id from secrets)
denied: select (select password from secrets limit 1) from orders
denied: select id from orders where exists (select 1 from secrets)
denied: with s as (select * from secrets) select id from orders
denied: select id from orders union select id from secrets
denied: select x.id from (select id from secrets) x
denied: select id from orders o join secrets s on s.id = o.id
unsupported: select * from mydb.public.orders

-- columns the policy does not name
denied: select secret from orders
denied: select tenant_id from orders
denied: select orders.secret from orders
denied: select o.secret from orders o
denied: select id from orders where secret = 'hidden'
denied: select id from orders order by secret
denied: select count(*) from orders group by secret
denied: select count(*) from orders having max(secret) > 'a'
denied: select o.id from orders o join customers c on c.email = o.product
denied: select max(secret) from orders
denied: select lower(secret) from orders
denied: select case when secret = 'hidden' then 1 else 0 end from orders
denied: select x.secret from (select * from orders) x
denied: select id from orders where id in (select customer_id from orders where secret is not null)
denied: select email from customers
denied: select hidden from app.events
denied: select c from limited
denied: select "ID" from orders
denied: select ctid from orders
denied: select xmin, xmax, tableoid from orders
denied: select oid from orders
denied: update orders set qty = 1 where secret = 'hidden'
denied: update orders set qty = length(secret) where id = 1
denied: update orders set qty = 1 where id = 1 returning secret
denied: delete from orders where secret = 'hidden'
denied: delete from orders where id = 1 returning secret
denied: insert into orders (product, qty) values ('a', 1) returning secret
denied: insert into audit (message) values ('x') returning id
denied: insert into audit (message) values ('x') returning *

-- whole-row references
denied: select orders from orders
denied: select o from orders o
unsupported: select (orders).secret from orders
denied: select count(orders) from orders
parse: select (o).* from orders o
parse: select o.*::text from orders o
unsupported: select row(o.*) from orders o
denied: select row_to_json(orders) from orders
denied: select to_json(o) from orders o
denied: select orders.orders from orders

-- names that cannot be resolved to one table
denied: select id from orders, customers
denied: select id from orders o1 join orders o2 on o1.id = o2.id
denied: select id from orders join orders on true
denied: select x.id from orders
denied: select id from v, cheap_orders
denied: with c as (select id from orders) select id from only c
denied: select id from only secrets

-- functions outside the allowed set
denied: select pg_sleep(10)
denied: select pg_sleep(10) from orders
denied: select pg_catalog.pg_sleep(10)
denied: select pg_read_file('/etc/passwd')
denied: select pg_read_binary_file('/etc/passwd')
denied: select pg_ls_dir('.')
denied: select lo_import('/etc/passwd')
denied: select dblink('host=evil', 'select 1')
denied: select query_to_xml('select * from secrets', true, true, '')
denied: select set_config('role', 'postgres', false)
denied: select current_setting('server_version')
denied: select version()
denied: select current_database()
denied: select inet_server_addr()
denied: select nextval('orders_id_seq')
denied: select setval('orders_id_seq', 1)
denied: select setseed(0.5)
denied: select pg_advisory_lock(1)
denied: select pg_notify('c', 'x')
denied: select pg_terminate_backend(1)
denied: select pg_cancel_backend(1)
denied: select to_regclass('secrets')
denied: select repeat('x', 1000000000)
denied: select lpad('x', 1000000000)
denied: select rpad('x', 1000000000)
denied: select format('%s', product) from orders
denied: select regexp_replace(product, '(a+)+$', '') from orders
denied: select regexp_match(product, 'a') from orders
denied: select regexp_split_to_array(product, 'a') from orders
denied: select generate_series(1, 1000000000)
denied: select unnest(tags) from v
denied: select jsonb_array_elements(data) from v
denied: select to_json(product), to_jsonb(product) from orders
denied: select jsonb_build_object('a', product) from orders
denied: select row_to_json(v) from v
denied: select evil.lower(product) from orders
denied: select public.count(*) from orders
denied: select mylower(product) from orders
denied: select id from orders where pg_sleep(qty) is null
denied: select id from orders order by pg_sleep(1)
denied: update orders set qty = nextval('orders_id_seq') where id = 1
denied: insert into orders (product, qty) values (version(), 1)
unsupported: select current_user
unsupported: select session_user from orders
unsupported: select user

-- operators
denied: select id from orders where product ~ '(a+)+$'
denied: select id from orders where product ~* 'a' or product !~ 'b' or product !~* 'c'
denied: select id from orders where product similar to '(a+)+'
denied: select id from (select id, product from orders) d where product ~ '^t'
denied: with d as (select id, product from orders) select id from d where product similar to 't%'
denied: select id from orders where id = (select max(o.id) from orders o where o.product ~ 'a')
denied: select id from orders o join customers c on c.name ~ o.product
denied: select 'a' ~ 'b'
unsupported: select id from orders where product = 'a' OPERATOR(pg_catalog.=) 'b'
unsupported: select id from orders where product OPERATOR(public.~~~) 'b'
unsupported: select id from orders where qty @@ 1
unsupported: select id from orders where qty <-> 1 > 0
unsupported: select id from orders where qty = any(select id from customers)
unsupported: select id from orders where qty > all(select id from customers)
unsupported: select qty # 1, qty & 1, qty | 1, qty << 1 from orders
unsupported: select @ qty, |/ qty, ~ qty from orders
unsupported: select qty ! from orders

-- casts to types outside the allowed set
unsupported: select 'secrets'::regclass
unsupported: select 'pg_sleep'::regproc
unsupported: select 'pg_sleep(float8)'::regprocedure
unsupported: select 'postgres'::regrole
unsupported: select cast(product as xml) from orders
unsupported: select product::evil.mytype from orders
unsupported: select product::text[] from orders
unsupported: select product::name from orders
unsupported: select id::oid from orders
unsupported: select regclass 'secrets'
unsupported: select _int4 '{1}' from orders
unsupported: select try_cast(product as int) from orders

-- literal forms p14g does not carry across
unsupported: select U&'d\0061t\+000061' from orders
unsupported: select X'41' from orders
unsupported: select B'1010' from orders
unsupported: select N'abc' from orders
unsupported: select id from orders where qty = 1L
parse: select id from orders where qty = ?
unsupported: select id from orders where qty = :name
unsupported: select id from orders where qty = $0
unsupported: select id from orders where qty = $name
unsupported: select id from orders where qty = $999999

-- identifiers
unsupported: select aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa from v
unsupported: select id as aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa from orders
unsupported: select id from orders as aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
unsupported: select "" from v
unsupported: select [id] from orders

-- star with nothing to expand
denied: select *
denied: select customers.* from orders
denied: select count(*) from orders order by 2
unsupported: select id from orders order by ''
unsupported: select id from orders order by null, id
unsupported: select id from orders order by (true)
unsupported: select count(*) from orders group by 'x'
unsupported: select count(*) from orders group by null
denied: select id from orders order by 1.5
denied: select id from orders union select id from customers order by 'x'

-- select syntax p14g has no representation for
unsupported: select id from orders for update
unsupported: select id from orders for share nowait
unsupported: select id into newtable from orders
unsupported: select id from orders natural join customers
unsupported: select orders.id from orders join customers using (id)
unsupported: select id from orders tablesample bernoulli (10)
unsupported: select o.id from orders o, lateral (select * from customers c where c.id = o.customer_id) x
unsupported: select * from generate_series(1, 10)
unsupported: select * from unnest(array[1, 2])
unsupported: select * from pg_ls_dir('.') as t
unsupported: select * from orders *
unsupported: select * from (orders o join customers c on c.id = o.customer_id)
unsupported: select * from (select 1)
unsupported: select * from (values (1), (2)) as t (a)
unsupported: select distinct on (customer_id) id from orders
unsupported: select id from orders fetch first 5 rows only
unsupported: select id from orders limit qty
unsupported: select id from orders limit (select count(*) from secrets)
unsupported: select id from orders group by rollup (id)
unsupported: select id from orders group by grouping sets ((id), ())
unsupported: select id, sum(qty) over w from orders window w as (partition by customer_id)
unsupported: select sum(qty) over (order by id rows between 1 preceding and current row) from orders
unsupported: select percentile_cont(0.5) within group (order by qty) from orders
unsupported: select id from orders order by id using <
unsupported: with recursive r as (select 1 as n union all select n + 1 from r) select n from r
unsupported: with d as (delete from orders where id = 1 returning id) select id from d
unsupported: with x (a) as (select id from orders) select a from x
unsupported: with x as materialized (select id from orders) select id from x
unsupported: select id from orders where (id, qty) = (1, 2)
unsupported: select id from orders where (id, qty) in (select id, qty from orders)
unsupported: select array[id, qty] from orders
unsupported: select array(select id from orders)
unsupported: select tags[1] from v
unsupported: select product collate "C" from orders
unsupported: select created at time zone 'UTC' from v
unsupported: select (data).k from v
unsupported: select lower(product => 'x') from orders
unsupported: select count(*) filter (where qty > 0) over () from orders where exists (table secrets)
unsupported: select coalesce(distinct qty, 1) from orders
unsupported: select nullif(qty) from orders
unsupported: select count(distinct *) from orders
unsupported: select count(* order by id) from orders
unsupported: select nullif(qty, 1, 2) from orders
unsupported: select coalesce() from orders
unsupported: select greatest() from orders
unsupported: select current_date(1) from orders
denied: select now from orders where now() > now
unsupported: select /*+ SeqScan(orders) */ id from orders
unsupported: select orders.id.x from orders

-- writes
denied: insert into customers (id, name) values (1, 'x')
denied: insert into secrets (id, password) values (1, 'x')
denied: insert into orders (product, secret) values ('tea', 'x')
denied: insert into orders (product, qty, tenant_id) values ('tea', 2, 1)
denied: insert into orders (tenant_id) values (1)
denied: insert into orders (product, product) values ('a', 'b')
denied: insert into orders (product, qty) values ((select password from secrets), 1)
denied: insert into orders (product, qty) values (product, 1)
unsupported: insert into orders values ('tea', 2)
unsupported: insert into orders (product, qty) values ('tea')
unsupported: insert into orders default values
denied: insert into orders (product, qty) values ('tea', default)
unsupported: insert into orders (product, qty) select product, qty from orders
unsupported: insert into orders (product, qty) select password, 1 from secrets
unsupported: insert into orders (product, qty) values ('tea', 2) on conflict do nothing
unsupported: insert into orders (product, qty) values ('tea', 2) on conflict (id) do update set secret = 'x'
unsupported: insert into orders (product, qty) overriding system value values ('tea', 2)
unsupported: insert into orders as o (product, qty) values ('tea', 2)
unsupported: insert into orders (orders.product, qty) values ('tea', 2)
denied: update customers set name = 'x' where id = 1
denied: update orders set product = 'x' where id = 1
denied: update orders set secret = 'x' where id = 1
denied: update orders set qty = 1, tenant_id = 2 where id = 1
denied: update orders set qty = 1, qty = 2 where id = 1
denied: update orders set qty = 1
denied: update orders set qty = (select count(*) from secrets) where id = 1
denied: update orders set qty = 1 where id in (select id from secrets)
unsupported: update orders set qty = 1 from secrets where secrets.id = orders.id
unsupported: update orders set qty = 1 from customers where customers.id = orders.customer_id
unsupported: update orders set (qty, product) = (1, 'x') where id = 1
denied: update orders set qty = default where id = 1
unsupported: update orders o join customers c on c.id = o.customer_id set qty = 1 where o.id = 1
denied: delete from customers where id = 1
denied: delete from secrets
denied: delete from orders
denied: delete from orders where id in (select id from secrets)
unsupported: delete from orders using secrets where secrets.id = orders.id
parse: delete from orders where current of c
