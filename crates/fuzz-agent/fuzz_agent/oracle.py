"""The checks made on every statement the agent tries. None of them takes the agent's word for anything.

They are the properties the libFuzzer targets check (`crates/fuzz/src/lib.rs`), against this package's policy:
no panic, output that Postgres's parser reads as one statement naming only allowed tables and functions, output
that reads back as itself, and a plan Postgres will make for a role with only the policy's grants.

Then the output is run, as the owner of the tables so that nothing but p14g stands in the way, in a transaction
that is rolled back. A canary in the result or in an error is a read that got through, and a change to a row the
policy does not allow is a write that got through.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import logfire
import pglast
import psycopg
from p14g import DEFAULT_FUNCTIONS
from pglast import visitors
from psycopg import conninfo, sql as pgsql
from psycopg.rows import dict_row, tuple_row

from . import target
from .target import Row
from .worker import Crashed, Hung, Mode, Rejected, Rewritten, Worker

DATABASE = 'p14g_agent'
OWNER = 'p14g_agent_owner'
ROLE = 'p14g_agent_role'

SLOW_REWRITE = 1.0
"""Seconds. The limits on a statement are meant to keep `rewrite()` far below this."""

HUNG_REWRITE = 10.0
"""Seconds after which `rewrite()` is given up on and its process killed."""

# functions the grammar turns syntax into: TRIM, LIKE ... ESCAPE
GRAMMAR_FUNCTIONS = frozenset({'btrim', 'like_escape'})

# what Postgres says when the output is wrong, not merely a statement that fails
POSTGRES_PROBLEMS = {
    '42501': ('permission', 'Postgres refused something the policy allowed'),
    '42601': ('postgres-parse', 'Postgres cannot parse the output'),
    '42P01': ('unknown-table', 'the output names a table that does not exist'),
}

Snapshot = dict[str, dict[Any, Row]]
_TABLES_WITH_EXTRA = frozenset(table for table, writes in target.WRITES.items() if writes.extra)


@dataclass
class Finding:
    kind: str
    detail: str
    input: str
    output: str | None = None


@dataclass
class Attempt:
    """One statement and everything that was learnt from it."""

    sql: str
    output: str | None = None
    """The rewritten SQL, with literals inline. `None` if the statement was rejected."""
    rejection: str | None = None
    tables: list[str] = field(default_factory=list[str])
    ran: str | None = None
    """What Postgres did with the output."""
    findings: list[Finding] = field(default_factory=list[Finding])

    def render(self) -> str:
        """The attempt as the agent is told about it."""
        lines: list[str] = []
        if self.output is None:
            lines.append(f'rejected: {self.rejection}')
        else:
            lines += ['accepted, rewritten to:', self.output]
        if self.ran is not None:
            lines += ['', self.ran]
        for finding in self.findings:
            lines += ['', f'FINDING ({finding.kind}): {finding.detail}']
        return '\n'.join(lines)


class Oracle:
    def __init__(self, database_url: str, worker: Worker | None = None):
        # p14g runs in `worker`, so that a statement that hangs it can be given up on
        self.worker = worker or Worker(timeout=HUNG_REWRITE)
        self.canaries = target.Canaries()
        self._lock = threading.Lock()
        self._owner, self._role = _set_up(database_url, self.canaries)
        self._before = self._snapshot()
        # from here on, so that each statement is a span but the rows put in by `_set_up` are not
        logfire.instrument_psycopg(self._owner)
        logfire.instrument_psycopg(self._role)

    def close(self) -> None:
        self.worker.close()
        self._owner.close()
        self._role.close()

    def attempt(self, sql: str) -> Attempt:
        with logfire.span('attempt', sql=sql) as span:
            attempt = self._attempt(sql)
            span.set_attributes(
                {
                    'accepted': attempt.output is not None,
                    'output': attempt.output,
                    'rejection': attempt.rejection,
                    'ran': attempt.ran,
                    'findings': [finding.kind for finding in attempt.findings],
                }
            )
        return attempt

    def _attempt(self, sql: str) -> Attempt:
        attempt = Attempt(sql)
        with self._lock:
            accepted: dict[Mode, Rewritten] = {}
            modes: tuple[Mode, ...] = ('inline', 'params')
            for mode in modes:
                safe = self._rewrite(mode, attempt)
                if safe is None:
                    continue
                accepted[mode] = safe
                attempt.tables = safe.tables
                self._check_structure(mode, safe, attempt)
                if mode == 'inline':
                    attempt.output = safe.sql
                    self._explain(attempt)
                    self._run(safe, attempt)
            if len(accepted) == 1:
                mode, safe = next(iter(accepted.items()))
                attempt.findings.append(
                    Finding(
                        'literal-mode',
                        f'the {mode} policy accepted the statement but the other literal mode rejected it',
                        sql,
                        safe.sql,
                    )
                )
        # both policies, and every row a statement touches, report the same thing
        attempt.findings = list({(finding.kind, finding.detail): finding for finding in attempt.findings}.values())
        return attempt

    def _rewrite(self, mode: Mode, attempt: Attempt) -> Rewritten | None:
        with logfire.span('rewrite {mode}', mode=mode) as span:
            start = time.perf_counter()
            outcome = self.worker.ask((mode, attempt.sql))
            took = time.perf_counter() - start
            match outcome:
                case Rewritten():
                    span.set_attributes({'output': outcome.sql, 'params': outcome.params, 'tables': outcome.tables})
                case Rejected():
                    # a rejection is the usual outcome, so it is an attribute and not an error on the span
                    attempt.rejection = f'{outcome.kind}: {outcome.message}'
                    span.set_attribute('rejection', attempt.rejection)
                case Crashed():
                    attempt.findings.append(Finding('panic', outcome.error, attempt.sql))
                    span.set_attribute('panic', outcome.error)
                case Hung():
                    detail = f'rewrite() had not returned after {outcome.seconds:.0f}s, so its process was killed'
                    attempt.findings.append(Finding('hang', detail, attempt.sql))
                    attempt.rejection = f'p14g did not answer within {outcome.seconds:.0f}s'
                    span.set_attribute('hang', detail)
                case _:
                    raise TypeError(f'unexpected answer from the worker: {outcome!r}')
        if took > SLOW_REWRITE and not isinstance(outcome, Hung):
            attempt.findings.append(Finding('slow', f'rewrite() took {took:.1f}s', attempt.sql))
        return outcome if isinstance(outcome, Rewritten) else None

    @logfire.instrument('check structure', extract_args=False)
    def _check_structure(self, mode: Mode, safe: Rewritten, attempt: Attempt) -> None:
        def found(kind: str, detail: str) -> None:
            attempt.findings.append(Finding(kind, detail, attempt.sql, safe.sql))

        try:
            statements = pglast.parse_sql(safe.sql)
        except pglast.Error as e:
            # Postgres itself says so when it plans the inline output, so only the parameterized output is reported
            if mode == 'params':
                found('postgres-parse', f"Postgres's parser cannot read the output: {e}")
            return None
        if len(statements) != 1:
            return found('multiple-statements', f'the output is {len(statements)} statements')

        reported = {_unqualified(table) for table in safe.tables}
        for table in sorted(visitors.referenced_relations(statements[0])):
            name = _unqualified(table)
            if name not in target.POLICY_TABLES:
                found('unknown-table', f'Postgres sees table {table!r}, which no rule names')
            elif name not in reported:
                found('unreported-table', f'table {table!r} is not in SafeSql.tables {safe.tables}')
        for function in sorted(_functions(statements[0])):
            name = function.removeprefix('pg_catalog.')
            if name not in DEFAULT_FUNCTIONS and name not in GRAMMAR_FUNCTIONS:
                found('function', f'Postgres sees function {function!r}, which is not allowed')

        # the output of a statement on a filtered table has the filter in it, and reading it back would apply
        # the filter a second time. The output of an insert has the `extra` columns, which a statement may not set
        if reported & target.FILTERED_TABLES or (safe.kind == 'insert' and reported & _TABLES_WITH_EXTRA):
            return None
        match self.worker.ask((mode, safe.sql)):
            case Rewritten(sql=again):
                if again != safe.sql:
                    found('not-idempotent', f'the output reads back as different SQL:\n{again}')
            case Rejected(kind=kind, message=message):
                # expanding `*` can push the output over a limit the input was under
                if kind != 'limit':
                    found('not-idempotent', f'p14g rejects its own output: {kind}: {message}')
            case Crashed(error=error):
                found('panic', f'reading the output back: {error}')
            case Hung(seconds=seconds):
                found('hang', f'reading the output back, rewrite() had not returned after {seconds:.0f}s')
            case other:
                raise TypeError(f'unexpected answer from the worker: {other!r}')

    @logfire.instrument('explain as the restricted role', extract_args=False)
    def _explain(self, attempt: Attempt) -> None:
        """Ask Postgres to plan the output for a role that has exactly the policy's grants."""
        assert attempt.output is not None
        try:
            self._role.execute(b'EXPLAIN ' + attempt.output.encode(), prepare=True)
        except psycopg.Error as e:
            if problem := POSTGRES_PROBLEMS.get(e.sqlstate or ''):
                kind, what = problem
                attempt.findings.append(Finding(kind, f'{what}: {_message(e)}', attempt.sql, attempt.output))

    @logfire.instrument('run as the owner', extract_args=False)
    def _run(self, safe: Rewritten, attempt: Attempt) -> None:
        def found(kind: str, detail: str) -> None:
            attempt.findings.append(Finding(kind, detail, attempt.sql, safe.sql))

        # tuples, not dicts: columns of a result can share a name (`?column?`), and a dict would keep only one
        rows: list[tuple[Any, ...]] = []
        after = self._before
        try:
            with self._owner.transaction(force_rollback=True):
                cursor = self._owner.cursor(row_factory=tuple_row)
                cursor.execute(safe.sql.encode(), prepare=True)
                if cursor.description is not None:
                    rows = cursor.fetchall()
                affected = cursor.rowcount
                after = self._snapshot()
        except psycopg.Error as e:
            message = _message(e)
            attempt.ran = f'Postgres error {e.sqlstate}: {message}'
            if leaked := self.canaries.found_in(message):
                found('error-leak', f'the error message holds a value from {", ".join(leaked)}: {message}')
            return

        shown = '\n'.join(_clip(str(list(row)), 300) for row in rows[:10])
        attempt.ran = f'ran: {affected} rows' + (f', the first {min(len(rows), 10)}:\n{shown}' if rows else '')
        if leaked := self.canaries.found_in(str(rows)):
            found('canary', f'the result holds a value from {", ".join(leaked)}')
        if safe.kind == 'select' and len(rows) > target.MAX_ROWS:
            found('max-rows', f'{len(rows)} rows came back and max_rows is {target.MAX_ROWS}')
        for problem in _forbidden_writes(self._before, after):
            found('forbidden-write', problem)

    def _snapshot(self) -> Snapshot:
        # the same queries every time, so they are left out of the trace
        with logfire.suppress_instrumentation():
            return {
                table: {
                    row['id']: row
                    for row in self._owner.execute(pgsql.SQL('SELECT * FROM ONLY {}').format(_table(table))).fetchall()
                }
                for table in target.WRITES
            }


def _set_up(database_url: str, canaries: target.Canaries) -> tuple[psycopg.Connection[Row], psycopg.Connection[Row]]:
    """Make the database from scratch, and connect to it as the owner of the tables and as the restricted role."""
    passwords = {OWNER: secrets.token_hex(16), ROLE: secrets.token_hex(16)}
    with psycopg.connect(database_url, autocommit=True) as admin:
        for role, password in passwords.items():
            exists = admin.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', [role]).fetchone()
            verb = pgsql.SQL('ALTER' if exists else 'CREATE')
            admin.execute(
                pgsql.SQL('{} ROLE {} LOGIN NOSUPERUSER PASSWORD {}').format(
                    verb, pgsql.Identifier(role), pgsql.Literal(password)
                )
            )
        admin.execute(pgsql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(pgsql.Identifier(DATABASE)))
        admin.execute(
            pgsql.SQL('CREATE DATABASE {} OWNER {}').format(pgsql.Identifier(DATABASE), pgsql.Identifier(OWNER))
        )

    def connect(role: str) -> psycopg.Connection[Row]:
        info = conninfo.make_conninfo(database_url, dbname=DATABASE, user=role, password=passwords[role])
        connection = psycopg.Connection[Row].connect(info, autocommit=True, row_factory=dict_row)
        connection.execute("SET statement_timeout = '2s'")
        return connection

    owner = connect(OWNER)
    owner.execute(target.SCHEMA.encode())
    for table, rows in target.rows(canaries).items():
        for row in rows:
            owner.execute(
                pgsql.SQL('INSERT INTO {} ({}) VALUES ({})').format(
                    _table(table),
                    pgsql.SQL(', ').join(map(pgsql.Identifier, row)),
                    pgsql.SQL(', ').join(pgsql.Placeholder() * len(row)),
                ),
                list(row.values()),
            )
    for grant in target.policy().grants(ROLE, context=target.CONTEXT):
        owner.execute(grant.encode())
    return owner, connect(ROLE)


def _forbidden_writes(before: Snapshot, after: Snapshot) -> list[str]:
    """Every change between two snapshots that `target.WRITES` does not allow."""
    problems: set[str] = set()
    for table, allowed in target.WRITES.items():
        was, now = before[table], after[table]
        for key in was.keys() - now.keys():
            if not allowed.delete:
                problems.add(f'a row of {table} was deleted')
            elif not allowed.reachable(was[key]):
                problems.add(f'a row of {table} outside the filter was deleted')
        for key in now.keys() - was.keys():
            if not allowed.insert:
                problems.add(f'a row was inserted into {table}')
                continue
            for column, value in now[key].items():
                if column in allowed.insert or column in allowed.defaulted:
                    continue
                expected = allowed.extra.get(column)
                if value != expected:
                    problems.add(f'a row was inserted into {table} with {column} = {value!r}, not {expected!r}')
        for key in was.keys() & now.keys():
            changed = {column for column, value in was[key].items() if now[key][column] != value}
            if not changed:
                continue
            if forbidden := changed - allowed.update:
                problems.add(f'{table}.{", ".join(sorted(forbidden))} was updated')
            if not allowed.reachable(was[key]):
                problems.add(f'a row of {table} outside the filter was updated')
    return sorted(problems)


class _Functions(visitors.Visitor):
    def __init__(self) -> None:
        super().__init__()
        self.names: set[str] = set()

    def visit_FuncCall(self, ancestors: Any, node: Any) -> None:
        self.names.add('.'.join(part.sval for part in node.funcname))


def _functions(statement: Any) -> set[str]:
    visitor = _Functions()
    visitor(statement)
    return visitor.names


def _unqualified(table: str) -> str:
    return table.removeprefix('public.')


def _table(name: str) -> pgsql.Identifier:
    return pgsql.Identifier(*name.split('.'))


def _message(error: psycopg.Error) -> str:
    return ' '.join(part for part in (error.diag.message_primary, error.diag.message_detail) if part)


def _clip(text: str, length: int) -> str:
    return text if len(text) <= length else f'{text[:length]}...'
