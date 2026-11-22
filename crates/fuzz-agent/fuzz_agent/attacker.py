"""The agent: a language model that reads p14g's source and writes SQL meant to get past it."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import logfire
from pydantic_ai import Agent, RunContext
from pydantic_ai.settings import ModelSettings
from pydantic_ai_harness import CodeMode
from pydantic_monty import MountDir

from . import library
from .oracle import Finding, Oracle

PACKAGE = Path(__file__).resolve().parent

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
  `/library`, with the same layout as the checkout. Read it with `pathlib` and search it with `re`, for example:

      import re
      from pathlib import Path

      for path in Path('/library/crates/p14g/src').rglob('*.rs'):
          for number, line in enumerate(path.read_text().splitlines(), 1):
              if re.search(r'fn member', line):
                  print(f'{path}:{number}: {line.strip()}')

  The sandbox runs a subset of Python: the standard library modules it has include `re`, `pathlib`, `json`,
  `asyncio`, `itertools` and `collections`, and not every method of each is there. Paths do not compare, so sort
  them with `key=str`. Print only what you need, as everything printed comes back to you.
- Read the source before guessing. The Rust under `/library/crates/p14g/src/` is the implementation,
  `/library/crates/p14g/tests/cases/reject.sql` is what has already been thought of, and `accept.sql` is what is
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
  next idea. A run that reads the whole library and tries nothing has found nothing.
- Use `report_finding` only for a real problem the checks cannot see, such as output that leaks through timing or
  through which error is raised, or an answer about rows you should not be able to count. Give the exact SQL.
  Do not report things the README documents as limits, such as an error raised before a row filter is applied.
- The database is rebuilt for each run and nothing you do to it is kept.

## Where to look

Work on one area at a time: unless the prompt names one, start where you think a bug is likeliest, go deeper where
a finding suggests there is more, and move on when an area stops giving you ideas.

These are some of the places where p14g's understanding of SQL and Postgres's could part. The list is not
complete: the bug worth finding may be somewhere it does not mention, so look beyond it, especially once you have
covered these.

- The writer (`crates/p14g/src/backend/`): string and identifier escaping, which names are left unquoted,
  keywords, where parentheses are left out, tokens that could run together or start a comment.
- Lowering (`crates/p14g/src/lower/`): syntax sqlparser accepts and Postgres reads differently, constructs
  rewritten on the way (POSITION, SUBSTRING, typed literals, casts), fields of a sqlparser node that are dropped
  or misread, and the input dialect.
- Name resolution (`crates/p14g/src/check.rs`): scopes, CTEs that shadow a table, aliases, derived tables,
  correlated subqueries, whole-row references, system columns, `*` expansion, and columns bound to a table other
  than the one Postgres will pick.
- The row filter on `docs` (`crates/p14g/src/filter.rs`, `Checker::filter_tables`, `Checker::write_filters`):
  every place a table can appear, aliases and CTEs named `docs`, set operations, subqueries inside writes, UPDATE
  and DELETE, and reading or changing rows of another org or status.
- Writes: columns an INSERT may not set, the values p14g adds to every insert, RETURNING, the right-hand side of
  SET, `ONLY family` and its child table, and tables that can only be inserted into.
- Operators, functions and types: the operator list, which leaves out regular expressions, the function
  allowlist and every overload of an allowed name, cast targets, and anything that reads server state or has a
  side effect.
- Limits and crashes: a panic, a statement that makes `rewrite()` slow, deep or wide input, and a SELECT that
  returns more than `max_rows` rows.

When you are out of ideas, stop and reply with a short summary: which areas you covered, what you tried, what p14g
did, and what you would try next. On your last turn you may not call `run_code`, and the reply you write then is
that summary.

## Start here

Read these in your first `run_code` call:

- `/library/README.md`: what p14g accepts and what it turns it into;
- `/library/AGENTS.md`: how the code is laid out;
- `/library/.agents/skills/review-security/SKILL.md`: the project's own security checklist;
- `/library/crates/fuzz-agent/fuzz_agent/target.py`: the database and policy you are attacking, and what the policy
  is meant to allow.
"""


READING_TURNS = 3
"""Turns the agent may spend reading before it is told to try a statement."""


@dataclass
class Session:
    """What one run of the fuzzer holds: the checks and the files it writes."""

    oracle: Oracle
    directory: Path
    turns: int = 40
    """Model requests in the run. The last may not call a tool, so that it is the summary."""
    attempts: int = 0
    accepted: int = 0
    findings: list[Finding] = field(default_factory=list[Finding])

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

    def last_turn(self, requests: int) -> bool:
        """Whether the request after `requests` made so far is the last the run's limit allows."""
        return requests >= self.turns - 1

    def turn_instructions(self, requests: int) -> str:
        """Instructions for the next request only: the summary on the last turn, and a push to start testing."""
        if self.last_turn(requests):
            return (
                'This is the last turn and you may not call `run_code`. Do not call or write out any tool call. '
                'Reply now, in plain text, with your summary: what you tried, what p14g did, and what you would try '
                'next.'
            )
        left = self.turns - requests
        if requests >= READING_TURNS and self.attempts == 0:
            return (
                f'You have not tried a statement yet and have {left} turns left. Stop reading and call '
                '`rewrite` from `run_code` now, with several statements at once.'
            )
        return f'You have {left} turns left, counting this one.'


agent = Agent(
    deps_type=Session,
    instructions=[INSTRUCTIONS, lambda ctx: ctx.deps.turn_instructions(ctx.usage.requests)],
    capabilities=[
        # `rewrite` and `report_finding` are called from Python in the sandbox, so one request can read files and
        # try a batch of statements
        CodeMode(mount=MountDir(host_path=library.PATH, virtual_path='/library', mode='read-only')),
    ],
    # on the last turn no tool may be called, so the reply is the summary
    model_settings=lambda ctx: ModelSettings(
        thinking='high', tool_choice='none' if ctx.deps.last_turn(ctx.usage.requests) else 'auto'
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
    flat = ' '.join(sql.split())
    print(f'{number:4} {"rejected" if attempt.output is None else "accepted"}: {flat[:120]}')
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
