"""Run the LLM fuzzer: `make fuzz-agent`, or `python -m fuzz_agent --help` from `crates/fuzz-agent`."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections import Counter
from datetime import datetime

from pydantic_ai import UsageLimitExceeded
from pydantic_ai.usage import RunUsage, UsageLimits

from . import attacker
from .attacker import FOCUS, PACKAGE, Session
from .judge import Judge
from .oracle import Oracle

# findings a person has to weigh up, as opposed to a check that failed
OPINIONS = {'judge', 'claimed'}


def parse_args() -> argparse.Namespace:
    gateway = 'PYDANTIC_AI_GATEWAY_API_KEY' in os.environ
    default_judge = 'typesafe:jev-latest' if 'TYPESAFE_API_KEY' in os.environ else None
    parser = argparse.ArgumentParser(prog='fuzz_agent', description=__doc__)
    parser.add_argument(
        '--model',
        default=os.environ.get('P14G_FUZZ_MODEL', f'{"gateway/" if gateway else ""}anthropic:claude-opus-5-5'),
        help='the model that writes the SQL, as a Pydantic AI model name (default: %(default)s)',
    )
    parser.add_argument(
        '--judge-model',
        default=os.environ.get('P14G_FUZZ_JUDGE_MODEL') or default_judge,
        help='a decision model, or a language model, asked whether each accepted statement breaks the policy '
        '(default: typesafe:jev-latest if TYPESAFE_API_KEY is set, otherwise no judge)',
    )
    parser.add_argument(
        '--judge-threshold', type=float, default=0.5, help='how likely a yes from a decision model has to be to count'
    )
    parser.add_argument('--rounds', type=int, default=len(FOCUS), help='rounds to run, each on one area of the library')
    parser.add_argument('--turns', type=int, default=40, help='model requests the agent gets in a round')
    parser.add_argument(
        '--focus', help='what to attack, in your own words, for every round; the default is a different area each round'
    )
    parser.add_argument(
        '--database-url',
        default=os.environ.get('P14G_TEST_DATABASE_URL'),
        help='a superuser connection to a throwaway Postgres (`make postgres`); the database p14g_agent is dropped '
        'and made again. Without one the output is checked but never run',
    )
    parser.add_argument('--logfire', action='store_true', help='send traces of the run to Pydantic Logfire')
    args = parser.parse_args()
    if not 0 <= args.judge_threshold <= 1:
        parser.error('--judge-threshold must be between 0 and 1')
    if args.rounds < 1:
        parser.error('--rounds must be at least 1')
    if args.turns < 1:
        parser.error('--turns must be at least 1')
    return args


async def run(args: argparse.Namespace) -> int:
    directory = PACKAGE.parent / 'runs' / datetime.now().strftime('%Y-%m-%dT%H-%M-%S-%f')
    directory.mkdir(parents=True)
    oracle = Oracle(args.database_url)
    judge = Judge(args.judge_model, args.judge_threshold) if args.judge_model else None
    session = Session(oracle, judge, directory)
    agent = attacker.build(args.model)

    print(f'model: {args.model}')
    print(f'judge: {args.judge_model or "none (set TYPESAFE_API_KEY or pass --judge-model)"}')
    print(f'database: {"statements are run" if oracle.has_database else "none, the output is checked but never run"}')
    print(f'writing to {directory}\n')

    usage = RunUsage()
    notes: list[str] = []
    for number in range(1, args.rounds + 1):
        focus = args.focus or FOCUS[(number - 1) % len(FOCUS)]
        print(f'round {number} of {args.rounds}: {focus.split(":")[0]}')
        prompt = f'This round, attack this area:\n\n{focus}\n\nYou have {args.turns} turns.'
        if notes:
            prompt += '\n\nSummaries of the rounds before this one:\n\n' + '\n\n'.join(notes)
        before = session.attempts
        # the limit is on the usage it is given, so each round has its own
        round_usage = RunUsage()
        try:
            result = await agent.run(
                prompt, deps=session, usage_limits=UsageLimits(request_limit=args.turns), usage=round_usage
            )
            summary = result.output
        except UsageLimitExceeded:
            summary = 'The round ran out of turns before a summary was written.'
        usage.incr(round_usage)
        found = sorted({f'{finding.kind}: {finding.detail.splitlines()[0]}' for finding in session.findings})
        note = f'## Round {number}: {focus}\n\n{summary}\n\n{session.attempts - before} statements tried.'
        if found:
            note += ' Findings recorded so far:\n' + '\n'.join(f'- {line}' for line in found)
        notes.append(note)
        (directory / 'notes.md').write_text('\n\n'.join(notes) + '\n')
        print(f'\n{summary}\n')

    kinds = Counter(finding.kind for finding in session.findings)
    print(f'{session.attempts} statements tried, {session.accepted} accepted')
    print(f'{usage.requests} requests, {usage.input_tokens} input and {usage.output_tokens} output tokens')
    for kind, count in sorted(kinds.items()):
        print(f'{count:4} {kind}')
    print(f'details in {directory}' if kinds else 'no findings')
    return 1 if kinds.keys() - OPINIONS else 0


def main() -> int:
    args = parse_args()
    if args.logfire:
        import logfire

        logfire.configure(service_name='p14g-fuzz-agent')
        logfire.instrument_pydantic_ai()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
