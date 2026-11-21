-- The database the accepted cases run against. `secrets`, and the columns of the other tables that the
-- test policy does not list, are there to be reached by mistake.
CREATE TABLE customers (id int PRIMARY KEY, name text, email text);
CREATE TABLE orders (
    id serial PRIMARY KEY,
    product text,
    qty int,
    customer_id int,
    tenant_id int,
    secret text DEFAULT 'hidden',
    created timestamptz DEFAULT now(),
    data jsonb DEFAULT '{"k": {"n": 1}, "list": [1, 2]}',
    tags text[] DEFAULT '{a,b}'
);
CREATE VIEW v AS SELECT id, product, qty, created, data, tags, 1 AS "a""b", 2 AS "MiXed" FROM orders;
CREATE SCHEMA app;
CREATE TABLE app.events (id int, kind text, hidden text);
CREATE TABLE limited (a int, b int, c int);
CREATE TABLE secrets (id int, password text);
CREATE TABLE audit (id serial PRIMARY KEY, message text, tenant_id int);
CREATE VIEW cheap_orders WITH (security_barrier = true) AS
    SELECT id, product, qty FROM orders WHERE qty < 10 WITH CHECK OPTION;

-- `family` has a child table: without ONLY, a query on `family` also reads and writes the child's rows
CREATE TABLE family (id int, label text);
CREATE TABLE family_child (extra text) INHERITS (family);
INSERT INTO family VALUES (1, 'parent'), (2, 'parent');
INSERT INTO family_child VALUES (10, 'child', 'x'), (11, 'child', 'y'), (12, 'child', 'z');

-- rows of two orgs, for rules with a filter
CREATE TABLE scoped (id int, val text, org int, hidden text);
INSERT INTO scoped VALUES (1, 'a', 1, 'h'), (2, 'b', 1, 'h'), (3, 'c', 2, 'h'), (4, 'd', 2, 'h'), (5, 'e', 2, 'h');

INSERT INTO customers VALUES (1, 'alice', 'a@example.com'), (2, 'bob', 'b@example.com');
INSERT INTO orders (product, qty, customer_id, tenant_id) VALUES ('tea', 2, 1, 42), ('coffee', 20, 2, 42), ('milk', 0, 1, 7);
INSERT INTO app.events VALUES (1, 'click', 'x');
INSERT INTO limited VALUES (1, 2, 3);
INSERT INTO secrets VALUES (1, 'hunter2');

-- grants that say the same thing as the policy in tests/common/mod.rs
GRANT USAGE ON SCHEMA app TO p14g_test_role;
GRANT SELECT (id, product, qty, customer_id) ON orders TO p14g_test_role;
GRANT INSERT (product, qty, tenant_id) ON orders TO p14g_test_role;
GRANT UPDATE (qty) ON orders TO p14g_test_role;
GRANT DELETE ON orders TO p14g_test_role;
GRANT USAGE ON SEQUENCE orders_id_seq TO p14g_test_role;
GRANT SELECT (id, name) ON customers TO p14g_test_role;
GRANT SELECT ON v TO p14g_test_role;
GRANT SELECT (id, kind) ON app.events TO p14g_test_role;
GRANT SELECT (a, b) ON limited TO p14g_test_role;
GRANT INSERT (message, tenant_id) ON audit TO p14g_test_role;
GRANT USAGE ON SEQUENCE audit_id_seq TO p14g_test_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON cheap_orders TO p14g_test_role;
GRANT SELECT (id, label), INSERT (id, label), UPDATE (label), DELETE ON family TO p14g_test_role;
GRANT SELECT (id, val, org), INSERT (id, val, org), UPDATE (val), DELETE ON scoped TO p14g_test_role;
