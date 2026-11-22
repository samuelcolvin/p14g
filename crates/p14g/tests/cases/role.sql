-- Statements that would change, reset or get around the role the output runs as, or the privileges and settings
-- that decide what it can reach. Nothing p14g accepts may do any of these, whatever the policy says.
-- One case per line, as in reject.sql: the error kind with the test policy, a colon, the SQL.
-- tests/role.rs also runs every case with each dialect and a more permissive policy, and needs only an error there.
--
-- The ways in, checked against Postgres 18:
-- * SET ROLE, SET SESSION AUTHORIZATION, RESET, DISCARD ALL, and set_config('role', ...) change it directly.
-- * COMMIT, ROLLBACK and ROLLBACK TO SAVEPOINT undo a SET LOCAL ROLE that the caller ran in the transaction.
-- * search_path, row_security and session_replication_role change what the role reaches without changing it.
--   UPDATE pg_settings is set_config by another name; it cannot set role, which pg_settings does not show.
-- * GRANT, ALTER ROLE, ownership and row-level security policies change what any role may do.
-- * DO, CALL, EXECUTE, functions, triggers, views and foreign servers run code as another role or later.
-- * Postgres reads t.f as the call f(t) when t has no column f, so a name that is not a column can be a call.
--   cases/schema.sql defines reset_role(t) for several tables. p14g only accepts names a select rule lists.
-- * A second statement after the first would be sent with it.

-- SET ROLE, SET SESSION AUTHORIZATION and their resets
unsupported: set role postgres
unsupported: set role none
parse: set role to default
unsupported: set local role postgres
unsupported: set session role postgres
unsupported: set "role" = 'postgres'
unsupported: set role = 'postgres'
unsupported: reset role
unsupported: reset "role"
unsupported: set session authorization postgres
unsupported: set session authorization default
parse: set local session authorization postgres
unsupported: reset session authorization
unsupported: reset session_authorization
unsupported: reset all
unsupported: discard all
unsupported: discard plans
-- settings that change what a name or a row resolves to
unsupported: set search_path = evil, public
unsupported: set local search_path to evil
unsupported: reset search_path
unsupported: set row_security = off
unsupported: set session_replication_role = replica
unsupported: set default_transaction_read_only = off
unsupported: set transaction read write
unsupported: set session characteristics as transaction read write
-- transaction control: ending or rolling back a transaction undoes SET LOCAL ROLE
unsupported: begin
unsupported: start transaction
unsupported: commit
unsupported: commit and chain
unsupported: end
unsupported: rollback
unsupported: abort
unsupported: savepoint a
unsupported: release savepoint a
unsupported: rollback to savepoint a
unsupported: rollback to a
parse: prepare transaction 'x'
parse: commit prepared 'x'
parse: rollback prepared 'x'
-- roles and privileges
unsupported: grant all on orders to public
unsupported: grant select on secrets to current_user
unsupported: grant postgres to current_user
unsupported: grant pg_read_all_data to p14g_test_role
unsupported: grant pg_write_all_data to public
unsupported: revoke all on orders from public
unsupported: revoke p14g_test_role from postgres
unsupported: create role evil superuser login
parse: create user evil with password 'x'
unsupported: alter role current_user superuser
unsupported: alter role current_user bypassrls
unsupported: alter role current_user set role = 'postgres'
unsupported: alter user p14g_test_role with createrole
unsupported: alter role all set search_path = evil
unsupported: alter role p14g_test_role rename to evil
unsupported: drop role p14g_test_role
unsupported: drop user if exists p14g_test_role
parse: alter database postgres set role = 'postgres'
parse: alter database postgres owner to p14g_test_role
parse: alter system set session_preload_libraries = 'evil'
unsupported: alter default privileges grant all on tables to public
parse: reassign owned by postgres to p14g_test_role
parse: drop owned by p14g_test_role
unsupported: alter table orders owner to p14g_test_role
unsupported: alter schema public owner to p14g_test_role
unsupported: alter table orders disable row level security
unsupported: alter table orders no force row level security
unsupported: create policy p on orders using (true)
unsupported: alter policy p on orders using (true)
unsupported: drop policy p on orders
parse: security label on role postgres is 'x'
-- code that runs as another role, later, or outside the statement
parse: do $$ begin execute 'set role postgres'; end $$
parse: do 'begin perform set_config(''role'', ''none'', false); end'
unsupported: create function f() returns void security definer language sql as 'select 1'
unsupported: create function f() returns void set role = 'postgres' language sql as 'select 1'
unsupported: create or replace function lower(text) returns text language sql as 'select $1'
unsupported: alter function f() security definer
unsupported: create view w as select 1
unsupported: create trigger t before insert on orders for each row execute function f()
unsupported: create extension dblink
unsupported: create server s foreign data wrapper postgres_fdw
unsupported: create user mapping for current_user server s options (user 'postgres')
unsupported: call p()
unsupported: prepare p as select 1
unsupported: execute p
unsupported: deallocate all
unsupported: load 'evil'
unsupported: copy orders from program 'id'
unsupported: copy (select 1) to program 'psql -c "alter role x superuser"'
unsupported: listen x
-- statements from other dialects that sqlparser knows
parse: use role accountadmin
parse: use secondary roles all
unsupported: execute as user = 'dbo'
parse: revert
unsupported: set names utf8
-- set_config, wherever a function call can go
denied: select set_config('role', 'postgres', false)
denied: select set_config('role', 'none', true)
denied: select set_config('session_authorization', 'postgres', false)
denied: select set_config('search_path', 'evil', false)
denied: select set_config('row_security', 'off', false)
denied: select pg_catalog.set_config('role', 'none', false)
denied: select "set_config"('role', 'none', false)
denied: select SET_CONFIG('role', 'none', false)
unsupported: select U&"\0073et_config"('role', 'none', false)
denied: select "pg_catalog"."set_config"('role', 'none', false)
unsupported: select * from set_config('role', 'none', false)
unsupported: select * from pg_catalog.set_config('role', 'none', false) as s
parse: select * from rows from (set_config('role', 'none', false))
unsupported: select id from orders, lateral set_config('role', 'none', false) s
unsupported: select id from orders cross join lateral (select set_config('role', 'none', false)) s
denied: select id from orders where set_config('role', 'none', false) is not null
denied: select id from orders order by set_config('role', 'none', false)
denied: select id from orders group by id, set_config('role', 'none', false)
denied: select id from orders where id = (select set_config('role', 'none', false)::int)
denied: select id from orders where exists (select set_config('role', 'none', false))
denied: with x as (select set_config('role', 'none', false)) select id from orders
denied: with x as (select set_config('role', 'none', false)) select * from x
denied: select id from orders union select set_config('role', 'none', false)::int
denied: insert into orders (product, qty) values (set_config('role', 'none', false), 1)
unsupported: insert into orders (product, qty) select set_config('role', 'none', false), 1
denied: update orders set qty = length(set_config('role', 'none', false)) where id = 1
denied: update orders set qty = 1 where id = 1 returning set_config('role', 'none', false)
denied: delete from orders where set_config('role', 'none', false) = 'none'
denied: select count(set_config('role', 'none', false)) from orders
denied: select coalesce(set_config('role', 'none', false), 'x')
denied: select case when true then set_config('role', 'none', false) end
denied: select cast(set_config('role', 'none', false) as text)
denied: select row_number() over (order by set_config('role', 'none', false)) from orders
denied: select count(*) filter (where set_config('role', 'none', false) = 'x') from orders
-- the pg_settings view, whose UPDATE rule calls set_config
denied: update pg_settings set setting = 'evil' where name = 'search_path'
denied: update pg_catalog.pg_settings set setting = 'off' where name = 'row_security'
denied: select * from pg_settings
denied: select set_config(name, 'x', false) from pg_settings
-- other functions that change the session or reach another one
denied: select dblink_exec('user=postgres', 'alter role p14g_test_role superuser')
denied: select dblink_connect('user=postgres')
denied: select pg_reload_conf()
denied: select pg_terminate_backend(pg_backend_pid())
-- a second statement hidden after the first
parse: select id from orders; set role postgres
parse: select id from orders; reset role
parse: select id from orders;reset role;
parse: select id from orders; commit
parse: select id from orders /* ; reset role */ ; reset role
parse: select 'a'; reset role; select 'b'
parse: select $$x$$; reset role
parse: select E'\''; reset role --'
parse: select 'x\'; reset role --'
-- built-in functions that run SQL given as text, which can call set_config
denied: select query_to_xml('select set_config(''role'', ''none'', false)', true, true, '')
denied: select query_to_xml_and_xmlschema('select 1', true, true, '')
denied: select pg_catalog.query_to_xml('select 1', true, true, '')
denied: select count(*) from orders where ts_stat('select 1') is not null
denied: select ts_rewrite(product, 'select 1') from orders
denied: select public.dblink('user=postgres', 'reset role')
-- a column reference that Postgres reads as a call, because the table has no column of that name
denied: select reset_role from orders
denied: select o.reset_role from orders o
denied: select v.reset_role from v
denied: select id from v where v.reset_role is not null
denied: select id from cheap_orders order by cheap_orders.reset_role
denied: select count(*) from customers group by customers.reset_role
denied: select x.reset_role from (select id from orders) x
denied: select v.row_to_json from v
denied: select v.to_jsonb from v
denied: select max(v.v) from v
