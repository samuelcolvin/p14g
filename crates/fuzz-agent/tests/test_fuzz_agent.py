from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fuzz_agent import attacker
from fuzz_agent.__main__ import usable_summary
from fuzz_agent.attacker import (
    Session,
    copy_repository,
    last_turn_without_tools,
    turn_instructions,
)
from fuzz_agent.oracle import Oracle
from fuzz_agent.worker import Worker
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel


def test_oracle(oracle: Oracle, tmp_path: Path) -> None:
    allowed = oracle.attempt('select id, name from customers')
    assert allowed.output == 'SELECT customers.id, customers.name\nFROM public.customers\nLIMIT 50'
    assert allowed.ran is not None and allowed.ran.startswith('ran: ')
    assert allowed.findings == []

    denied = oracle.attempt('select email from customers')
    assert denied.output is None
    assert denied.rejection == 'denied: column "email" is not allowed'
    assert denied.findings == []

    filtered = oracle.attempt('select * from docs')
    assert filtered.output is not None
    assert 'docs.org = 7' in filtered.output
    assert "docs.status IN ('draft', 'published')" in filtered.output
    assert filtered.findings == []

    session = Session(oracle, tmp_path)
    assert 'crates/p14g/src/check.rs' in session.files
    assert '.claude/skills' not in session.files


def test_hang_is_a_finding_and_the_worker_restarts(database_url: str) -> None:
    from handlers import rewrite_unless_marked

    oracle = Oracle(database_url, worker=Worker(rewrite_unless_marked, timeout=1))
    try:
        hung = oracle.attempt("select id from customers where name = 'HANG'")
        assert hung.output is None
        assert [finding.kind for finding in hung.findings] == ['hang']
        assert hung.rejection == 'p14g did not answer within 1s'

        died = oracle.attempt("select id from customers where name = 'DIE'")
        assert [finding.kind for finding in died.findings] == ['panic']
        assert died.findings[0].detail == 'the worker process died'

        # a new process answers the next statement
        after = oracle.attempt('select id from customers')
        assert after.output == 'SELECT customers.id\nFROM public.customers\nLIMIT 50'
        assert after.findings == []
    finally:
        oracle.close()


def test_turns() -> None:
    tools: list[Any] = ['rewrite', 'read_file']

    def context(requests: int, attempts: int = 0) -> Any:
        deps = SimpleNamespace(turns=5, attempts=attempts, round_start=0)
        return SimpleNamespace(usage=SimpleNamespace(requests=requests), deps=deps)

    assert last_turn_without_tools(context(0), tools) == tools
    assert last_turn_without_tools(context(3), tools) == tools
    # the fifth request, after four, is the last the round allows
    assert last_turn_without_tools(context(4), tools) == []

    assert turn_instructions(context(0)) == 'You have 5 turns left in this round, counting this one.'
    assert turn_instructions(context(3)).startswith('You have not tried a statement this round')
    assert turn_instructions(context(3, attempts=2)) == 'You have 2 turns left in this round, counting this one.'
    assert turn_instructions(context(4)).startswith('This is the last turn of the round')


def test_usable_summary() -> None:
    assert usable_summary('Tried nested stars; all rejected.') == 'Tried nested stars; all rejected.'
    pretend = '<tool_call>read_file<arg_value>first_line</arg_key><arg_value>200</arg_value></tool_call>'
    assert usable_summary(pretend) == 'The model wrote no summary.'
    assert usable_summary('  ') == 'The model wrote no summary.'


# what the scripted model runs in the sandbox: read the mounted copy, try to write to it, and try a statement
CODE = """
from pathlib import Path
print(Path('/repo/crates/p14g/src/check.rs').read_text().splitlines()[0])
print(Path('/repo/.env').exists())
try:
    Path('/repo/written').write_text('x')
except PermissionError:
    print('read-only')
print(await rewrite(sql='select id from customers'))
"""


def test_code_mode(oracle: Oracle, tmp_path: Path) -> None:
    tools_offered: list[list[str]] = []
    returned: list[str] = []

    def model(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        tools_offered.append([tool.name for tool in info.function_tools])
        returns = [part for message in messages for part in message.parts if isinstance(part, ToolReturnPart)]
        if returns or not info.function_tools:
            returned.extend(str(part.content) for part in returns)
            return ModelResponse(parts=[TextPart('summary')])
        return ModelResponse(parts=[ToolCallPart('run_code', {'code': CODE})])

    session = Session(oracle, tmp_path, turns=5)
    copy_repository(session.files)

    def run() -> str:
        return attacker.agent.run_sync('attack', model=FunctionModel(model), deps=session).output

    assert run() == 'summary'
    # the file tools are gone: the agent reads the mounted copy and calls `rewrite` from Python
    assert tools_offered == [['run_code'], ['run_code']]
    [output] = returned
    assert 'read-only' in output
    assert 'False' in output
    assert 'SELECT customers.id' in output
    assert session.tried == ['accepted: select id from customers']
    assert not (attacker.REPOSITORY / 'written').exists()

    # on the last turn of a round there is no `run_code` either, so the reply is the summary
    tools_offered.clear()
    session.turns = 1
    assert run() == 'summary'
    assert tools_offered == [[]]
