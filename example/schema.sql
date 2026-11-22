-- Run as a superuser on a database dedicated to this example: `make setup` does that, then runs the grants
-- `policy.grants('example_untrusted')` returns. It drops and recreates everything, so it can be rerun.
--
-- `example_owner` owns the tables. The server uses it to write the audit log.
-- `example_untrusted` has the grants for the SQL p14g writes. It cannot log in, owns nothing and cannot bypass
--   row-level security. An app with several levels of access would have one such role for each.
-- `example_authenticator` is what the server's pool logs in as. It has no privileges of its own; each transaction
--   switches to `example_untrusted` with `set_config('role', ..., true)`. One pool serves every such role, however
--   many there are.

drop schema if exists app cascade;
-- `drop owned` also removes the roles' privileges, without which `drop role` fails
do $$
declare
    r text;
begin
    foreach r in array array['example_authenticator', 'example_untrusted', 'example_owner'] loop
        if exists (select from pg_roles where rolname = r) then
            execute format('drop owned by %I', r);
            execute format('drop role %I', r);
        end if;
    end loop;
end $$;

create role example_owner login password 'owner';
create role example_untrusted nologin nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
create role example_authenticator login password 'authenticator'
    nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication connection limit 20;

-- The authenticator may switch to the untrusted role, but does not get its privileges until it does.
-- It must never be a member of `example_owner`: a statement that managed to run `set role` could reach any role
-- the authenticator is a member of.
grant example_untrusted to example_authenticator with inherit false, set true;

-- Limits for every connection the server opens. They go on the role that logs in: `set role` does not apply the
-- settings of the role it switches to. p14g does not bound how much work a query does.
alter role example_authenticator set statement_timeout = '2s';
alter role example_authenticator set lock_timeout = '1s';
alter role example_authenticator set idle_in_transaction_session_timeout = '5s';
-- memory for each sort or hash in a query; past it, the query writes temporary files
alter role example_authenticator set work_mem = '4MB';
-- temporary files per process; unlimited by default, so a large sort could fill the disk
alter role example_authenticator set temp_file_limit = '100MB';
-- one query uses one process
alter role example_authenticator set max_parallel_workers_per_gather = 0;
alter role example_authenticator set search_path = app;
alter role example_authenticator set client_encoding = 'UTF8';

-- Nothing in `public`, and no access to the database except for the two roles.
revoke all on schema public from public;
do $$ begin
    execute format('revoke all on database %I from public', current_database());
    execute format('grant connect on database %I to example_owner, example_authenticator', current_database());
end $$;

create schema app authorization example_owner;
set role example_owner;
set search_path = app;

-- Reference data every user may read.
create table countries (
    code text primary key check (code ~ '^[A-Z]{2}$'),
    name text not null
);

create table organisations (
    id uuid primary key default uuidv7(),
    name text not null,
    plan text not null default 'free' check (plan in ('free', 'team', 'enterprise')),
    stripe_customer_id text
);

create table users (
    id uuid primary key default uuidv7(),
    org_id uuid not null references organisations,
    email text not null unique,
    name text not null,
    password_hash text not null,
    created_at timestamptz not null default now(),
    -- the target of the composite foreign key from `tasks`
    unique (org_id, id)
);

create table projects (
    id uuid primary key default uuidv7(),
    org_id uuid not null references organisations,
    name text not null,
    country_code text references countries,
    created_at timestamptz not null default now(),
    unique (org_id, id)
);

create table tasks (
    id uuid primary key default uuidv7(),
    org_id uuid not null references organisations,
    project_id uuid not null,
    assignee_id uuid,
    title text not null,
    status text not null default 'todo' check (status in ('todo', 'doing', 'done')),
    due_date date,
    created_at timestamptz not null default now(),
    -- Composite keys, so a task cannot point at another org's project or user even if the id is guessed.
    -- Foreign keys are checked without row-level security, so a plain `references projects` would let a
    -- statement attach a task to any project in the database.
    foreign key (org_id, project_id) references projects (org_id, id) on delete cascade,
    foreign key (org_id, assignee_id) references users (org_id, id)
);

-- Tables untrusted SQL never reaches. They are not in the policy and the role has no grant on them.
create table api_keys (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users on delete cascade,
    key_hash text not null unique,
    created_at timestamptz not null default now()
);

create table invoices (
    id uuid primary key default uuidv7(),
    org_id uuid not null references organisations,
    amount_cents bigint not null,
    issued_at date not null
);

create table audit_log (
    id uuid primary key default uuidv7(),
    org_id uuid not null,
    sql_in text not null,
    sql_out text,
    error text,
    at timestamptz not null default now()
);

-- Row-level security. The condition matches the p14g filter in policy.py: the filter limits what a statement
-- returns and changes, RLS stops the statement learning anything about rows outside the org (see "Why you should use
-- `filter` and RLS together" in the p14g README). `current_setting(..., true)` is null when the setting is missing,
-- so a connection that has not set it sees no rows.
alter table organisations enable row level security;
create policy by_org on organisations
    using (id = current_setting('app.org_id', true)::uuid);

alter table users enable row level security;
create policy by_org on users
    using (org_id = current_setting('app.org_id', true)::uuid);

alter table projects enable row level security;
create policy by_org on projects
    using (org_id = current_setting('app.org_id', true)::uuid)
    with check (org_id = current_setting('app.org_id', true)::uuid);

alter table tasks enable row level security;
create policy by_org on tasks
    using (org_id = current_setting('app.org_id', true)::uuid)
    with check (org_id = current_setting('app.org_id', true)::uuid);

-- RLS with no policy denies every row, should a grant on one of these ever be added by mistake.
alter table api_keys enable row level security;
alter table invoices enable row level security;
alter table audit_log enable row level security;

-- Seed data. Organisations, users and projects have fixed ids so policy.py and the tests can refer to them:
-- organisations are 1000..., users 2000... and projects 3000.... Anne and Bob are in Acme, Charlie in Globex.
insert into countries (code, name) values
    ('GB', 'United Kingdom'), ('US', 'United States'), ('FR', 'France'), ('DE', 'Germany'), ('JP', 'Japan');

insert into organisations (id, name, plan, stripe_customer_id) values
    ('10000000-0000-4000-8000-000000000001', 'Acme', 'team', 'cus_acme123'),
    ('10000000-0000-4000-8000-000000000002', 'Globex', 'enterprise', 'cus_globex456');

insert into users (id, org_id, email, name, password_hash) values
    ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'anne@acme.example', 'Anne', '$argon2id$v=19$m=65536,t=3,p=4$YW5uZQ$not-a-real-hash-1'),
    ('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'bob@acme.example', 'Bob', '$argon2id$v=19$m=65536,t=3,p=4$Ym9i$not-a-real-hash-2'),
    ('20000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', 'charlie@globex.example', 'Charlie', '$argon2id$v=19$m=65536,t=3,p=4$Y2hhcmxpZQ$not-a-real-hash-3');

-- Secrets that untrusted SQL must never reach; the server does not use them.
insert into api_keys (user_id, key_hash) values
    ('20000000-0000-4000-8000-000000000001', encode(sha256('acme-anne-key'), 'hex')),
    ('20000000-0000-4000-8000-000000000002', encode(sha256('acme-bob-key'), 'hex')),
    ('20000000-0000-4000-8000-000000000003', encode(sha256('globex-charlie-key'), 'hex'));

insert into projects (id, org_id, name, country_code) values
    ('30000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'Rocket skates', 'US'),
    ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'Giant magnet', 'GB'),
    ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', 'Hammock factory', 'DE'),
    ('30000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000002', 'Project Arcturus', 'JP');

-- in one statement, so their uuidv7 ids are in this order
insert into tasks (org_id, project_id, assignee_id, title, status, due_date) values
    ('10000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'Order wheels', 'done', '2026-10-01'),
    ('10000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002', 'Fit rocket', 'doing', '2026-12-01'),
    ('10000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000001', 'Source magnet', 'todo', '2027-01-15'),
    ('10000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000003', 'Find a site', 'done', '2026-09-30'),
    ('10000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000003', 'Hire weavers', 'doing', null),
    ('10000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000004', '20000000-0000-4000-8000-000000000003', 'Classified', 'todo', '2027-03-01');

insert into invoices (org_id, amount_cents, issued_at) values
    ('10000000-0000-4000-8000-000000000001', 49900, '2026-10-01'), ('10000000-0000-4000-8000-000000000001', 49900, '2026-11-01'), ('10000000-0000-4000-8000-000000000002', 1250000, '2026-11-01');

reset role;
