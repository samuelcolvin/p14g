"""What the agent attacks: a database, a policy over it, and what that policy is meant to allow.

The agent reads this file first, so it is written to be read. Everything the policy does not allow holds a canary:
a random value made when the database is set up, which the agent is never told. A canary in a result, or in an
error message from Postgres, means something was read that should not have been.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from p14g import Delete, Insert, Policy, Select, Update
from typing_extensions import LiteralString

Row = dict[str, Any]

CONTEXT: dict[str, Any] = {'org': 7, 'tenant': 42, 'actor': 'fuzz-agent'}
"""Passed to every `rewrite()`. The SQL author does not choose it."""

STATUSES = ['draft', 'published']
MAX_ROWS = 50


def docs_filter(context: dict[str, Any]) -> tuple[LiteralString, dict[str, Any]]:
    return 'org = :org and status in (:statuses)', {'org': context['org'], 'statuses': STATUSES}


def policy(**options: Any) -> Policy:
    return Policy(
        # some columns of a table
        Select('customers', columns=['id', 'name']),
        Select('orders', columns=['id', 'product', 'qty', 'customer_id']),
        Insert('orders', columns=['product', 'qty'], extra=lambda context: {'tenant_id': context['tenant']}),
        Update('orders', columns=['qty']),
        Delete('orders'),
        # a view, all of its columns
        Select('v'),
        # a table in another schema
        Select('app.events', columns=['id', 'kind']),
        Select('limited', columns=['a', 'b']),
        # insert only: nothing in `audit` can be read back
        Insert(
            'audit',
            columns=['message'],
            extra=lambda context: {'tenant_id': context['tenant'], 'actor': context['actor']},
        ),
        # a table with an inheritance child, `family_child`, that must not be reached
        Select('family', columns=['id', 'label'], only=True),
        Insert('family', columns=['id', 'label']),
        Update('family', columns=['label'], only=True),
        Delete('family', only=True),
        # rows: only the caller's org, and only two statuses. `org`, `status` and `internal` cannot be set, and
        # `org` and `internal` cannot be read
        Select('docs', columns=['id', 'title', 'body', 'status'], filter=docs_filter),
        Insert('docs', columns=['title', 'body'], extra=lambda context: {'org': context['org'], 'status': 'draft'}),
        Update('docs', columns=['title', 'body'], filter=docs_filter),
        Delete('docs', filter=docs_filter),
        default_schema='public',
        max_rows=MAX_ROWS,
        **options,
    )


# `secrets` is in no rule. Neither is `family_child`.
SCHEMA = """
CREATE TABLE customers (id int PRIMARY KEY, name text, email text);
CREATE TABLE orders (
    id serial PRIMARY KEY, product text, qty int, customer_id int, tenant_id int, secret text,
    created timestamptz DEFAULT now(), data jsonb DEFAULT '{}'
);
CREATE VIEW v AS SELECT id, product, qty, created, data FROM orders;
CREATE SCHEMA app;
CREATE TABLE app.events (id int PRIMARY KEY, kind text, hidden text);
CREATE TABLE limited (id int PRIMARY KEY, a int, b int, c int);
CREATE TABLE audit (id serial PRIMARY KEY, message text, tenant_id int, actor text);
CREATE TABLE secrets (id int PRIMARY KEY, password text);
CREATE TABLE family (id int PRIMARY KEY, label text);
CREATE TABLE family_child (extra text) INHERITS (family);
CREATE TABLE docs (id serial PRIMARY KEY, title text, body text, org int, status text, internal text);
"""


@dataclass(frozen=True)
class Writes:
    """What a statement may change in one table."""

    insert: frozenset[str] = frozenset()
    """Columns the statement may give a value for."""
    extra: Mapping[str, Any] = field(default_factory=dict[str, Any])
    """Values every inserted row has, whatever the statement says."""
    defaulted: frozenset[str] = frozenset({'id'})
    """Columns the database fills in. Every other column of an inserted row is null."""
    update: frozenset[str] = frozenset()
    delete: bool = False
    reachable: Callable[[Row], bool] = lambda row: True
    """Whether an update or delete may touch this row, given the row as it was before."""


# Every table that holds rows. A table with the default `Writes()` must never change.
WRITES: dict[str, Writes] = {
    'customers': Writes(),
    'orders': Writes(
        insert=frozenset({'product', 'qty'}),
        extra={'tenant_id': CONTEXT['tenant']},
        defaulted=frozenset({'id', 'created', 'data'}),
        update=frozenset({'qty'}),
        delete=True,
    ),
    'app.events': Writes(),
    'limited': Writes(),
    'audit': Writes(
        insert=frozenset({'message'}),
        extra={'tenant_id': CONTEXT['tenant'], 'actor': CONTEXT['actor']},
    ),
    'secrets': Writes(),
    'family': Writes(
        insert=frozenset({'id', 'label'}), defaulted=frozenset(), update=frozenset({'label'}), delete=True
    ),
    'family_child': Writes(),
    'docs': Writes(
        insert=frozenset({'title', 'body'}),
        extra={'org': CONTEXT['org'], 'status': 'draft'},
        update=frozenset({'title', 'body'}),
        delete=True,
        reachable=lambda row: row['org'] == CONTEXT['org'] and row['status'] in STATUSES,
    ),
}

POLICY_TABLES = frozenset({'customers', 'orders', 'v', 'app.events', 'limited', 'family', 'docs', 'audit'})
FILTERED_TABLES = frozenset({'docs'})


@dataclass
class Canaries:
    """Hands out canaries and remembers where each one was put."""

    placed: dict[str, str] = field(default_factory=dict[str, str])

    def text(self, where: str) -> str:
        value = f'cnry{secrets.token_hex(6)}'
        self.placed[value] = where
        return value

    def number(self, where: str) -> int:
        # ten digits, so it is not a count, a sum of small numbers or an id
        value = 1_000_000_000 + secrets.randbelow(1_000_000_000)
        self.placed[str(value)] = where
        return value

    def found_in(self, text: str) -> list[str]:
        """Where the canaries in `text` came from."""
        return sorted({where for value, where in self.placed.items() if value in text})


def rows(canaries: Canaries) -> dict[str, list[Row]]:
    """The rows of every table. The same shape each run, with new canaries."""
    orders = [
        {
            'product': ['tea', 'coffee', 'milk', 'sugar'][n % 4],
            'qty': n % 25,
            'customer_id': n % 20 + 1,
            'tenant_id': canaries.number('orders.tenant_id'),
            'secret': canaries.text('orders.secret'),
        }
        # more rows than `max_rows`
        for n in range(200)
    ]
    docs: list[Row] = []
    for n in range(10):
        docs.append({'title': f'doc {n}', 'body': 'visible', 'org': 7, 'status': STATUSES[n % 2]})
    for n in range(5):
        # the caller's org, but a status the filter leaves out
        docs.append({'title': canaries.text('docs: archived row'), 'body': 'x', 'org': 7, 'status': 'archived'})
    for n in range(10):
        docs.append(
            {
                'title': canaries.text('docs: row of another org'),
                'body': canaries.text('docs: row of another org'),
                'org': canaries.number('docs.org'),
                'status': STATUSES[n % 2],
            }
        )
    for doc in docs:
        doc['internal'] = canaries.text('docs.internal')
    return {
        'customers': [
            {'id': n, 'name': f'customer {n}', 'email': canaries.text('customers.email')} for n in range(1, 21)
        ],
        'orders': orders,
        'app.events': [{'id': n, 'kind': 'click', 'hidden': canaries.text('app.events.hidden')} for n in range(1, 6)],
        'limited': [{'id': n, 'a': n, 'b': n * 2, 'c': canaries.number('limited.c')} for n in range(1, 6)],
        'audit': [
            {'message': canaries.text('audit.message'), 'tenant_id': canaries.number('audit.tenant_id'), 'actor': 'x'}
            for _ in range(5)
        ],
        'secrets': [{'id': n, 'password': canaries.text('secrets.password')} for n in range(1, 4)],
        'family': [{'id': n, 'label': 'parent'} for n in range(1, 6)],
        'family_child': [
            {'id': n, 'label': canaries.text('family_child.label'), 'extra': canaries.text('family_child.extra')}
            for n in range(100, 105)
        ],
        'docs': docs,
    }
