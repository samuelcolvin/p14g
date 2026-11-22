"""The agent: a language model that reads p14g's source and writes SQL meant to get past it."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import logfire
from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import AbstractCapability, CapabilityOrdering
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModelSettings
from pydantic_ai.tools import ToolDefinition
from pydantic_ai.toolsets import AbstractToolset, PreparedToolset
from pydantic_ai_harness import CodeMode
from pydantic_monty import MountDir

from .oracle import Finding, Oracle

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = Path(__file__).resolve().parent

# shown to the agent in full; it can read anything else in the repository from `run_code`
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

- You have one tool, `run_code`, which runs Python in a sandbox. Inside it, `await rewrite(sql=...)` and
  `await report_finding(...)` are the functions described below, and the repository is a read-only directory at
  `/repo`, with the same layout as the checkout. Read it with `pathlib` and search it with `re`, for example:

      import re
      from pathlib import Path

      for path in Path('/repo/crates/p14g/src').rglob('*.rs'):
          for number, line in enumerate(path.read_text().splitlines(), 1):
              if re.search(r'fn member', line):
                  print(f'{path}:{number}: {line.strip()}')

  The sandbox runs a subset of Python: the standard library modules it has include `re`, `pathlib`, `json`,
  `asyncio`, `itertools` and `collections`, and not every method of each is there. Paths do not compare, so sort
  them with `key=str`. Print only what you need, as everything printed comes back to you.
- Read the source before guessing. The Rust under `/repo/crates/p14g/src/` is the implementation,
  `/repo/crates/p14g/tests/cases/reject.sql` is what has already been thought of, and `accept.sql` is what is
  known to work.
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
- You have a limited number of turns, and one `run_code` call can do a lot: read several files, or try a batch of
  statements in a loop or with `asyncio.gather`, printing what each one returned.
- Reading is only worth what it leads you to try. Call `rewrite` within your first three or four turns, and from
  then on try statements in most turns, several at once, reading more only to explain a result or to find the
  next idea. A round that reads the whole library and tries nothing has found nothing.
- Use `report_finding` only for a real problem the checks cannot see, such as output that leaks through timing or
  through which error is raised, or an answer about rows you should not be able to count. Give the exact SQL.
  Do not report things the README documents as limits, such as an error raised before a row filter is applied.
- The database is rebuilt for each run and nothing you do to it is kept.

When you are out of ideas for the area you were given, stop and reply with a short summary: what you tried, what
p14g did, and what you would try next. On your last turn `run_code` is taken away, and the reply you write then
is that summary. The next round starts from it and nothing else you saw.

## Reference

The files below are the project's documentation, its own security checklist, and the definition of the database
and policy you are attacking.
"""


@dataclass
class Session:
    """What one run of the fuzzer holds: the checks and the files it writes."""

    oracle: Oracle
    directory: Path
    turns: int = 40
    """Model requests in a round. The last has no tools, so that it is the round's summary."""
    round_start: int = 0
    """`attempts` when the current round began."""
    attempts: int = 0
    accepted: int = 0
    findings: list[Finding] = field(default_factory=list[Finding])
    tried: list[str] = field(default_factory=list[str])
    """One line per statement: what happened to it, then the statement. The next round is shown this."""
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


def copy_repository(files: frozenset[str], destination: Path) -> Path:
    """Copy `files` from the checkout to `destination`, which the agent's sandbox mounts read-only.

    The checkout itself is not mounted: it has `.env`, the virtual environment and the runs of this fuzzer in it.
    """
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return destination


def instructions() -> str:
    parts = [INSTRUCTIONS]
    for name in BRIEFING:
        parts.append(f'<file path="{name}">\n{(ROOT / name).read_text()}\n</file>')
    return '\n\n'.join(parts)


TESTING_BY = 3
"""Requests after which a round that has tried no statement is told to."""


def _last_turn(ctx: RunContext[Session]) -> bool:
    # `requests` counts the requests already made, so this is the last one the round's limit allows
    return ctx.usage.requests >= ctx.deps.turns - 1


def last_turn_without_tools(ctx: RunContext[Session], tool_defs: list[ToolDefinition]) -> list[ToolDefinition]:
    return [] if _last_turn(ctx) else tool_defs


@dataclass
class LastTurnWithoutTools(AbstractCapability[Session]):
    """Offer no tools on the round's last request, so that its reply is the summary.

    It wraps `CodeMode`, so it sees `run_code` itself: a `prepare_tools` hook is applied inside `CodeMode` and only
    sees the tools `run_code` calls, so `run_code` would still be offered.
    """

    def get_ordering(self) -> CapabilityOrdering:
        return CapabilityOrdering(position='outermost', wraps=[CodeMode])

    def get_wrapper_toolset(self, toolset: AbstractToolset[Session]) -> AbstractToolset[Session]:
        return PreparedToolset(toolset, last_turn_without_tools)


def turn_instructions(ctx: RunContext[Session]) -> str:
    """Instructions for this request only: the summary on the last turn, and a push to start testing."""
    if _last_turn(ctx):
        return (
            'This is the last turn of the round and the tools are gone. Do not call or write out any tool call. '
            'Reply now, in plain text, with the summary of the round: what you tried, what p14g did, and what you '
            'would try next.'
        )
    left = ctx.deps.turns - ctx.usage.requests
    if ctx.usage.requests >= TESTING_BY and ctx.deps.attempts == ctx.deps.round_start:
        return (
            f'You have not tried a statement this round and have {left} turns left. Stop reading and call '
            '`rewrite` from `run_code` now, with several statements at once.'
        )
    return f'You have {left} turns left in this round, counting this one.'


def build(model: Model | str, repository: Path) -> Agent[Session, str]:
    """The agent, with `repository`, a copy made by `copy_repository`, mounted read-only at `/repo`."""
    mount = MountDir(host_path=repository, virtual_path='/repo', mode='read-only')
    agent = Agent(
        model,
        deps_type=Session,
        instructions=[instructions(), turn_instructions],
        capabilities=[
            LastTurnWithoutTools(),
            # `rewrite` and `report_finding` are called from Python in the sandbox, so one request can read
            # files and try a batch of statements
            CodeMode(mount=mount),
        ],
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
        status = 'rejected' if attempt.output is None else 'accepted'
        flat = ' '.join(sql.split())
        print(f'{number:4} {status}: {flat[:120]}')
        outcome = 'accepted' if attempt.output is not None else f'rejected ({(attempt.rejection or "")[:100]})'
        if attempt.findings:
            outcome += ', FINDING ' + ', '.join(finding.kind for finding in attempt.findings)
        session.tried.append(f'{outcome}: {flat[:160]}')
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

    return agent
