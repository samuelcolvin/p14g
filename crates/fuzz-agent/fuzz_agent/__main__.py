"""Run the LLM fuzzer: `make fuzz-agent`, or `python -m fuzz_agent --help` from `crates/fuzz-agent`."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections import Counter
from datetime import datetime

import logfire
from pydantic_ai import UsageLimitExceeded
from pydantic_ai.exceptions import ModelAPIError, UnexpectedModelBehavior
from pydantic_ai.models import Model, infer_model
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers import Provider, infer_provider

# overloads for providers whose clients are not installed (groq, google) have unknown types; ours takes a `str`
from pydantic_ai.providers.gateway import gateway_provider  # pyright: ignore[reportUnknownVariableType]
from pydantic_ai.usage import RunUsage, UsageLimits

from . import attacker
from .attacker import FOCUS, PACKAGE, Session
from .judge import Judge
from .oracle import Oracle

# findings a person has to weigh up, as opposed to a check that failed
OPINIONS = {'judge', 'claimed'}

TRIED_IN_NOTES = 60
"""How many of a round's statements the rounds after it are shown."""


def usable_summary(text: str) -> str:
    """The model's summary, or a note that there is none when it wrote out a tool call instead.

    Some models, GLM among them, answer a turn without tools with the text of a tool call.
    """
    if not text.strip() or '<tool_call>' in text or '<arg_value>' in text:
        return 'The model wrote no summary.'
    return text


def parse_args() -> argparse.Namespace:
    default_judge = 'typesafe:jev-latest' if 'TYPESAFE_API_KEY' in os.environ else None
    parser = argparse.ArgumentParser(prog='fuzz_agent', description=__doc__)
    parser.add_argument(
        '--model',
        default=os.environ.get('P14G_FUZZ_MODEL', 'gateway/doubleword:zai-org/GLM-5.3'),
        help='the model that writes the SQL, as a Pydantic AI model name; a `gateway/` model is reached through '
        'the Pydantic AI Gateway with LOGFIRE_API_KEY (default: %(default)s)',
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
    args = parser.parse_args()
    if args.model.startswith('gateway/') and 'LOGFIRE_API_KEY' not in os.environ:
        parser.error(
            f'{args.model} goes through the Pydantic AI Gateway: set LOGFIRE_API_KEY to a key made with '
            '`logfire-cli api-key write gateway`'
        )
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
    try:
        judge = Judge(args.judge_model, args.judge_threshold) if args.judge_model else None
        session = Session(oracle, judge, directory, turns=args.turns)
        agent = attacker.build(model(args.model))

        print(f'model: {args.model}')
        print(f'judge: {args.judge_model or "none (set TYPESAFE_API_KEY or pass --judge-model)"}')
        print(
            f'database: {"statements are run" if oracle.has_database else "none, the output is checked but never run"}'
        )
        sending = bool(logfire.DEFAULT_LOGFIRE_INSTANCE.config.token)
        print(f'traces: {"sent to Logfire" if sending else "not sent, set LOGFIRE_API_KEY"}')
        print(f'writing to {directory}\n')

        usage = RunUsage()
        notes: list[str] = []
        with logfire.span(
            'fuzz run {model}', model=args.model, judge=args.judge_model, rounds=args.rounds, directory=str(directory)
        ) as run_span:
            for number in range(1, args.rounds + 1):
                focus = args.focus or FOCUS[(number - 1) % len(FOCUS)]
                print(f'round {number} of {args.rounds}: {focus.split(":")[0]}')
                prompt = f'This round, attack this area:\n\n{focus}\n\nYou have {args.turns} turns.'
                if notes:
                    prompt += '\n\nSummaries of the rounds before this one:\n\n' + '\n\n'.join(notes)
                before = (session.attempts, len(session.findings))
                tried_before = len(session.tried)
                session.round_start = session.attempts
                # the limit is on the usage it is given, so each round has its own
                round_usage = RunUsage()
                with logfire.span('round {number}', number=number, focus=focus) as round_span:
                    try:
                        result = await agent.run(
                            prompt, deps=session, usage_limits=UsageLimits(request_limit=args.turns), usage=round_usage
                        )
                        summary = usable_summary(result.output)
                    except UsageLimitExceeded:
                        summary = 'The round ran out of turns before a summary was written.'
                    except (ModelAPIError, UnexpectedModelBehavior) as e:
                        # a provider refusing a request, or an answer that cannot be used, ends the round, not the run
                        summary = f'The round stopped on a model error: {type(e).__name__}: {str(e)[:500]}'
                    round_span.set_attributes(
                        {
                            'summary': summary,
                            'attempts': session.attempts - before[0],
                            'findings': len(session.findings) - before[1],
                        }
                    )
                usage.incr(round_usage)
                found = sorted({f'{finding.kind}: {finding.detail.splitlines()[0]}' for finding in session.findings})
                note = f'## Round {number}: {focus}\n\n{summary}\n\n{session.attempts - before[0]} statements tried.'
                if found:
                    note += ' Findings recorded so far:\n' + '\n'.join(f'- {line}' for line in found)
                # kept by the fuzzer, so the next round knows what was tried whether or not the model summarised it
                tried = session.tried[tried_before:]
                if tried:
                    shown = tried[-TRIED_IN_NOTES:]
                    skipped = f' (the last {len(shown)} of {len(tried)})' if len(shown) < len(tried) else ''
                    note += f'\n\nStatements tried{skipped}:\n' + '\n'.join(f'- {line}' for line in shown)
                notes.append(note)
                (directory / 'notes.md').write_text('\n\n'.join(notes) + '\n')
                print(f'\n{summary}\n')

            kinds = Counter(finding.kind for finding in session.findings)
            run_span.set_attributes(
                {'attempts': session.attempts, 'accepted': session.accepted, 'findings': dict(kinds)}
            )
        print(f'{session.attempts} statements tried, {session.accepted} accepted')
        print(f'{usage.requests} requests, {usage.input_tokens} input and {usage.output_tokens} output tokens')
        for kind, count in sorted(kinds.items()):
            print(f'{count:4} {kind}')
        print(f'details in {directory}' if kinds else 'no findings')
        return 1 if kinds.keys() - OPINIONS else 0
    finally:
        oracle.close()


def model(name: str) -> Model:
    """The model called `name`, with `gateway/` models given LOGFIRE_API_KEY.

    One Logfire API key with the `write` and `gateway` permissions (`logfire-cli api-key write gateway`) sends the
    traces and pays for the model requests.
    """

    api_key = os.environ.get('LOGFIRE_API_KEY')
    # Pydantic AI has no Doubleword provider, but Doubleword speaks OpenAI's chat API and the Gateway routes to it
    if name.startswith('gateway/doubleword:'):
        provider = gateway_provider('openai-chat', route='doubleword', api_key=api_key)
        return OpenAIChatModel(name.removeprefix('gateway/doubleword:'), provider=provider)

    def provider_for(provider_name: str) -> Provider[object]:
        if provider_name.startswith('gateway/'):
            return gateway_provider(provider_name.removeprefix('gateway/'), api_key=api_key)
        return infer_provider(provider_name)

    return infer_model(name, provider_for)


def main() -> int:
    args = parse_args()
    # progress is printed as it happens, also when the output goes to a file or a pipe
    if reconfigure := getattr(sys.stdout, 'reconfigure', None):
        reconfigure(line_buffering=True)
    # sent to Logfire when LOGFIRE_API_KEY is set; the console output is our own
    # no scrubbing: the database is thrown away and its secrets are random canaries, and a trace with
    # `secrets.password` or `auth` scrubbed out hides what the agent tried
    logfire.configure(
        service_name='p14g-fuzz-agent', send_to_logfire='if-token-present', console=False, scrubbing=False
    )
    logfire.instrument_pydantic_ai()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
