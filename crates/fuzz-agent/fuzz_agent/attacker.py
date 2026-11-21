"""The agent: a language model that reads p14g's source and writes SQL meant to get past it."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import logfire
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModelSettings

from .judge import Judge
from .oracle import Finding, Oracle

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = Path(__file__).resolve().parent

# shown to the agent in full; it can read anything else in the repository with its tools
BRIEFING = [
    'README.md',
    'AGENTS.md',
    '.agents/skills/review-security/SKILL.md',
    'crates/fuzz-agent/fuzz_agent/target.py',
]

# one per round, so that a run covers the library and does not spend itself on the first idea
FOCUS = [
    (
        'The writer (`crates/p14g/src/backend/`): string and identifier escaping, which names are left unquoted, '
        'keywords, where parentheses are left out, tokens that could run together or start a comment.'
    ),
    (
        'Lowering (`crates/p14g/src/lower/`): syntax sqlparser accepts and Postgres reads differently, constructs '
        'rewritten on the way (POSITION, SUBSTRING, typed literals, casts), fields of a sqlparser node that are '
        'dropped or misread, and the input dialect.'
    ),
    (
        'Name resolution (`crates/p14g/src/check.rs`): scopes, CTEs that shadow a table, aliases, derived tables, '
        'correlated subqueries, whole-row references, system columns, `*` expansion, and columns bound to a table '
        'other than the one Postgres will pick.'
    ),
    (
        'The row filter on `docs` (`crates/p14g/src/filter.rs`, `Checker::filter_tables`, `Checker::write_filters`): '
        'every place a table can appear, aliases and CTEs named `docs`, set operations, subqueries inside writes, '
        'UPDATE and DELETE, and reading or changing rows of another org or status.'
    ),
    (
        'Writes: columns an INSERT may not set, the values p14g adds to every insert, RETURNING, the right-hand side '
        'of SET, `ONLY family` and its child table, and tables that can only be inserted into.'
    ),
    (
        'Operators, functions and types: the operator list, which leaves out regular expressions, the function allowlist and every overload '
        'of an allowed name, cast targets, and anything that reads server state or has a side effect.'
    ),
    (
        'Limits and crashes: a panic, a statement that makes `rewrite()` slow, deep or wide input, and a SELECT that '
        'returns more than `max_rows` rows.'
    ),
]

INSTRUCTIONS = """\
You are testing the security of p14g, at the request of its author, on their own machine and a throwaway database.

p14g takes SQL from an untrusted author, checks it against a policy, and returns rewritten SQL that is meant to be
safe to run on Postgres. Your job is to be that untrusted author and find SQL that p14g accepts and should not
have: SQL that reads a table, column or row the policy does not allow, writes one, calls a function that is not
allowed, comes out as something Postgres reads differently from how p14g understood it, or makes p14g panic or
hang. A bug in p14g is the goal. The policy author, the `context` and the database setup are trusted and are not
yours to change.

## How to work

- Read the source before guessing. `read_file`, `list_files` and `search` cover the whole repository. The Rust
  under `crates/p14g/src/` is the implementation, `crates/p14g/tests/cases/reject.sql` is what has already been
  thought of, and `accept.sql` is what is known to work.
- Form a specific hypothesis about one piece of code ("`member` does not quote keywords, so a column named X after
  a dot ..."), then test it with `rewrite`. Statements that are plainly forbidden, such as
  `select password from secrets`, are rejected and teach you nothing. Look for the place where p14g's model of the
  SQL and Postgres's differ.
- `rewrite` is the only way to learn whether something worked. It runs p14g on your SQL with the target policy,
  then checks the output without relying on you:
    - Postgres's own parser must read it as one statement naming only allowed tables and functions;
    - p14g must read its own output back as the same SQL;
    - Postgres must be willing to plan it for a role that has only the policy's grants;
    - it is run as the owner of the tables, in a transaction that is rolled back. Every value the policy does
      not allow you to read is a random canary, so a canary in the result or in an error message is a leak, and
      any change to a row the policy does not allow is caught by comparing the tables before and after.
  A line starting `FINDING` in the result means a check failed. That is a success: it is recorded for you, so move
  on to a different idea, or find out how far it goes.
- Call several tools in one turn when the calls do not depend on each other. You have a limited number of turns.
- Reading is only worth what it leads you to try. Call `rewrite` within your first three or four turns, and from
  then on try statements in most turns, several at once, reading more only to explain a result or to find the
  next idea. A round that reads the whole library and tries nothing has found nothing.
- Use `report_finding` only for a real problem the checks cannot see, such as output that leaks through timing or
  through which error is raised, or an answer about rows you should not be able to count. Give the exact SQL.
  Do not report things the README documents as limits, such as an error raised before a row filter is applied.
- The database is rebuilt for each run and nothing you do to it is kept.

When you are out of ideas for the area you were given, or nearly out of turns, stop and reply with a short
summary: what you tried, what p14g did, and what you would try next. The next round starts from that summary and
nothing else you saw.

## Reference

The files below are the project's documentation, its own security checklist, and the definition of the database
and policy you are attacking.
"""


@dataclass
class Session:
    """What one run of the fuzzer holds: the checks, the judge, and the files it writes."""

    oracle: Oracle
    judge: Judge | None
    directory: Path
    attempts: int = 0
    accepted: int = 0
    findings: list[Finding] = field(default_factory=list[Finding])
    judge_failures: int = 0
    _files: frozenset[str] | None = None

    def record(self, name: str, entry: dict[str, Any]) -> None:
        with (self.directory / f'{name}.jsonl').open('a') as f:
            f.write(json.dumps(entry) + '\n')

    def found(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.record('findings', asdict(finding))
        logfire.warn(
            'finding {kind}: {detail}',
            kind=finding.kind,
            detail=finding.detail,
            input=finding.input,
            output=finding.output,
        )
        print(f'  FINDING ({finding.kind}): {finding.detail.splitlines()[0][:150]}')

    @property
    def files(self) -> frozenset[str]:
        """Files the agent may read: those git tracks or would track, so nothing ignored and nothing outside."""
        if self._files is None:
            listed = subprocess.run(
                ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            root = ROOT.resolve()
            files: set[str] = set()
            for name in listed.stdout.splitlines():
                path = ROOT / name
                try:
                    path.resolve().relative_to(root)
                except ValueError:
                    continue
                if path.is_file():
                    files.add(name)
            self._files = frozenset(files)
        return self._files

    def path(self, name: str) -> Path:
        name = name.strip().removeprefix('./').rstrip('/')
        if name not in self.files:
            raise ModelRetry(f'{name!r} is not a file in the repository; use list_files to see what there is')
        return ROOT / name


def instructions() -> str:
    parts = [INSTRUCTIONS]
    for name in BRIEFING:
        parts.append(f'<file path="{name}">\n{(ROOT / name).read_text()}\n</file>')
    return '\n\n'.join(parts)


def build(model: Model | str) -> Agent[Session, str]:
    agent = Agent(
        model,
        deps_type=Session,
        instructions=instructions(),
        model_settings=AnthropicModelSettings(
            thinking='high',
            # the briefing is long and the same on every request; other providers ignore these
            anthropic_cache_instructions=True,
            anthropic_cache_tool_definitions=True,
            anthropic_cache_messages=True,
        ),
        retries=3,
    )

    @agent.tool
    async def rewrite(ctx: RunContext[Session], sql: str) -> str:
        """Run p14g on a statement with the target policy, run every check on the output, and say what happened.

        Args:
            sql: One SQL statement, exactly as the untrusted author would send it.
        """
        session = ctx.deps
        session.attempts += 1
        # the agent calls this tool several at a time, so each call keeps its own number
        number = session.attempts
        # written before anything is run, so a statement that crashes the process is the last line of the file
        session.record('attempts', {'n': number, 'sql': sql})
        attempt = await asyncio.to_thread(session.oracle.attempt, sql)
        if attempt.output is not None:
            session.accepted += 1
            if judgment := await _judge(session, sql, attempt.output):
                # the agent is not told: it would learn to write SQL that worries the judge
                model, flags = judgment
                session.found(Finding('judge', f'{model}: {", ".join(flags)}', sql, attempt.output))
        status = 'rejected' if attempt.output is None else 'accepted'
        print(f'{number:4} {status}: {" ".join(sql.split())[:120]}')
        for finding in attempt.findings:
            session.found(finding)
        return attempt.render()

    @agent.tool
    def report_finding(ctx: RunContext[Session], title: str, sql: str, explanation: str) -> str:
        """Record a problem that the checks behind `rewrite` cannot see.

        Args:
            title: The problem in one line.
            sql: The exact statement that shows it.
            explanation: What p14g did, what it should have done, and why it matters.
        """
        ctx.deps.found(Finding('claimed', f'{title}\n{explanation}', sql))
        return 'recorded'

    @agent.tool
    def list_files(ctx: RunContext[Session], directory: str = '') -> str:
        """List the files of the repository under a directory.

        Args:
            directory: A path relative to the repository root, such as `crates/p14g/src`. Empty for everything.
        """
        prefix = directory.strip().removeprefix('./').strip('/')
        names = sorted(name for name in ctx.deps.files if not prefix or name.startswith(f'{prefix}/'))
        return '\n'.join(names) or f'nothing under {directory!r}'

    @agent.tool
    def read_file(ctx: RunContext[Session], path: str, first_line: int = 1, lines: int = 400) -> str:
        """Read a file of the repository, with line numbers.

        Args:
            path: A path relative to the repository root, such as `crates/p14g/src/check.rs`.
            first_line: The line to start from.
            lines: How many lines to return, at most 800.
        """
        try:
            text = ctx.deps.path(path).read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            return f'{path} is not text'
        start = max(first_line, 1) - 1
        chunk = text[start : start + min(max(lines, 1), 800)]
        body = '\n'.join(f'{start + n + 1:5}  {line}' for n, line in enumerate(chunk))
        return f'{path}, lines {start + 1} to {start + len(chunk)} of {len(text)}\n{body}'

    @agent.tool
    def search(ctx: RunContext[Session], pattern: str, directory: str = 'crates/p14g') -> str:
        """Search the repository's files for a regular expression, and return the matching lines.

        Args:
            pattern: A Python regular expression, matched against each line.
            directory: Only search files under this path. Empty for everything.
        """
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise ModelRetry(f'not a regular expression: {e}') from e
        prefix = directory.strip().removeprefix('./').strip('/')
        matches: list[str] = []
        for name in sorted(ctx.deps.files):
            if prefix and not name.startswith(f'{prefix}/') and name != prefix:
                continue
            try:
                text = (ROOT / name).read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(f'{name}:{number}: {line.strip()[:200]}')
                    if len(matches) == 100:
                        return '\n'.join(matches) + '\n(stopped at 100 matches)'
        return '\n'.join(matches) or 'no matches'

    return agent


async def _judge(session: Session, input_sql: str, output_sql: str) -> tuple[str, list[str]] | None:
    if session.judge is None:
        return None
    try:
        model, flags = await session.judge.flags(input_sql, output_sql)
    except Exception as e:  # noqa: BLE001 - whatever goes wrong with the judge, the run carries on
        session.judge_failures += 1
        print(f'  the judge failed: {type(e).__name__}: {str(e)[:200]}')
        if session.judge_failures >= 3:
            print('  three failures, carrying on without the judge')
            session.judge = None
        return None
    session.judge_failures = 0
    return (model, flags) if flags else None
