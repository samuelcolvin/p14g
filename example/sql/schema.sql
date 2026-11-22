-- Run as a superuser on a database dedicated to this example: `make setup` does that, then runs the grants
-- `policy.grants('example_untrusted')` returns. It drops and recreates everything, so it can be rerun.
--
-- `example_owner` owns the tables. The server uses it to look up API keys and write the audit log.
-- `example_untrusted` runs the SQL p14g writes. It owns nothing and cannot bypass row-level security.

drop schema if exists app cascade;
-- `drop owned` also removes the roles' privileges, without which `drop role` fails
do $$ begin
    if exists (select from pg_roles where rolname = 'example_untrusted') then
        drop owned by example_untrusted;
    end if;
    if exists (select from pg_roles where rolname = 'example_owner') then
        drop owned by example_owner;
    end if;
end $$;
drop role if exists example_untrusted;
drop role if exists example_owner;

create role example_owner login password 'owner';
create role example_untrusted login password 'untrusted'
    nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication connection limit 20;

-- Limits for every connection as the untrusted role. p14g does not bound how much work a query does.
alter role example_untrusted set statement_timeout = '2s';
alter role example_untrusted set lock_timeout = '1s';
alter role example_untrusted set idle_in_transaction_session_timeout = '5s';
alter role example_untrusted set search_path = app;
alter role example_untrusted set client_encoding = 'UTF8';

-- Nothing in `public`, and no access to the database except for the two roles.
revoke all on schema public from public;
do $$ begin
    execute format('revoke all on database %I from public', current_database());
    execute format('grant connect on database %I to example_owner, example_untrusted', current_database());
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
    id bigint generated always as identity primary key,
    name text not null,
    plan text not null default 'free' check (plan in ('free', 'team', 'enterprise')),
    stripe_customer_id text
);

create table users (
    id bigint generated always as identity primary key,
    org_id bigint not null references organisations,
    email text not null unique,
    name text not null,
    password_hash text not null,
    created_at timestamptz not null default now(),
    -- the target of the composite foreign key from `tasks`
    unique (org_id, id)
);

create table projects (
    id bigint generated always as identity primary key,
    org_id bigint not null references organisations,
    name text not null,
    country_code text references countries,
    created_at timestamptz not null default now(),
    unique (org_id, id)
);

create table tasks (
    id bigint generated always as identity primary key,
    org_id bigint not null references organisations,
    project_id bigint not null,
    assignee_id bigint,
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
    id bigint generated always as identity primary key,
    user_id bigint not null references users on delete cascade,
    key_hash text not null unique,
    created_at timestamptz not null default now()
);

create table invoices (
    id bigint generated always as identity primary key,
    org_id bigint not null references organisations,
    amount_cents bigint not null,
    issued_at date not null
);

create table audit_log (
    id bigint generated always as identity primary key,
    org_id bigint not null,
    user_id bigint not null,
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
    using (id = current_setting('app.org_id', true)::bigint);

alter table users enable row level security;
create policy by_org on users
    using (org_id = current_setting('app.org_id', true)::bigint);

alter table projects enable row level security;
create policy by_org on projects
    using (org_id = current_setting('app.org_id', true)::bigint)
    with check (org_id = current_setting('app.org_id', true)::bigint);

alter table tasks enable row level security;
create policy by_org on tasks
    using (org_id = current_setting('app.org_id', true)::bigint)
    with check (org_id = current_setting('app.org_id', true)::bigint);

-- RLS with no policy denies every row, should a grant on one of these ever be added by mistake.
alter table api_keys enable row level security;
alter table invoices enable row level security;
alter table audit_log enable row level security;

-- Seed data. Ids are assigned in insert order: Acme is org 1, Globex org 2.
insert into countries (code, name) values
    ('GB', 'United Kingdom'), ('US', 'United States'), ('FR', 'France'), ('DE', 'Germany'), ('JP', 'Japan');

insert into organisations (name, plan, stripe_customer_id) values
    ('Acme', 'team', 'cus_acme123'),
    ('Globex', 'enterprise', 'cus_globex456');

insert into users (org_id, email, name, password_hash) values
    (1, 'alice@acme.example', 'Alice', '$argon2id$v=19$m=65536,t=3,p=4$YWNtZWFsaWNl$not-a-real-hash-1'),
    (1, 'bob@acme.example', 'Bob', '$argon2id$v=19$m=65536,t=3,p=4$YWNtZWJvYg$not-a-real-hash-2'),
    (2, 'carol@globex.example', 'Carol', '$argon2id$v=19$m=65536,t=3,p=4$Z2xvYmV4Y2Fyb2w$not-a-real-hash-3'),
    (2, 'dan@globex.example', 'Dan', '$argon2id$v=19$m=65536,t=3,p=4$Z2xvYmV4ZGFu$not-a-real-hash-4');

-- The keys themselves are in the README; only their SHA-256 is stored.
insert into api_keys (user_id, key_hash)
select u.id, encode(sha256(convert_to(k.key, 'UTF8')), 'hex')
from (values
    ('alice@acme.example', 'acme-alice-key'),
    ('bob@acme.example', 'acme-bob-key'),
    ('carol@globex.example', 'globex-carol-key'),
    ('dan@globex.example', 'globex-dan-key')
) as k (email, key)
join users u on u.email = k.email;

insert into projects (org_id, name, country_code) values
    (1, 'Rocket skates', 'US'),
    (1, 'Giant magnet', 'GB'),
    (2, 'Hammock factory', 'DE'),
    (2, 'Project Arcturus', 'JP');

insert into tasks (org_id, project_id, assignee_id, title, status, due_date) values
    (1, 1, 1, 'Order wheels', 'done', '2026-10-01'),
    (1, 1, 2, 'Fit rocket', 'doing', '2026-12-01'),
    (1, 2, 1, 'Source magnet', 'todo', '2027-01-15'),
    (2, 3, 3, 'Find a site', 'done', '2026-09-30'),
    (2, 3, 4, 'Hire weavers', 'doing', null),
    (2, 4, 3, 'Classified', 'todo', '2027-03-01');

insert into invoices (org_id, amount_cents, issued_at) values
    (1, 49900, '2026-10-01'), (1, 49900, '2026-11-01'), (2, 1250000, '2026-11-01');

reset role;
