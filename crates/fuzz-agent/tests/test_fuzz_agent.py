from __future__ import annotations

from pathlib import Path
from typing import cast

from fuzz_agent import attacker, library
from fuzz_agent.__main__ import usable_summary
from fuzz_agent.attacker import Session
from fuzz_agent.oracle import Oracle
from fuzz_agent.worker import Worker
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel


def test_oracle(oracle: Oracle) -> None:
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

    files = library.files()
    assert 'crates/p14g/src/check.rs' in files
    assert '.env' not in files


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


def test_turns(tmp_path: Path) -> None:
    session = Session(cast(Oracle, None), tmp_path, turns=5)

    assert not session.last_turn(0)
    assert not session.last_turn(3)
    # the fifth request, after four, is the last the round allows
    assert session.last_turn(4)

    assert session.turn_instructions(0) == 'You have 5 turns left in this round, counting this one.'
    assert session.turn_instructions(3).startswith('You have not tried a statement this round')
    session.attempts = 2
    assert session.turn_instructions(3) == 'You have 2 turns left in this round, counting this one.'
    assert session.turn_instructions(4).startswith('This is the last turn of the round')


def test_usable_summary() -> None:
    assert usable_summary('Tried nested stars; all rejected.') == 'Tried nested stars; all rejected.'
    pretend = '<tool_call>read_file<arg_value>first_line</arg_key><arg_value>200</arg_value></tool_call>'
    assert usable_summary(pretend) == 'The model wrote no summary.'
    assert usable_summary('  ') == 'The model wrote no summary.'


# what the scripted model runs in the sandbox: read the mounted copy, try to write to it, and try a statement
CODE = """
from pathlib import Path
print(Path('/library/crates/p14g/src/check.rs').read_text().splitlines()[0])
print(Path('/library/.env').exists())
try:
    Path('/library/written').write_text('x')
except PermissionError:
    print('read-only')
print(await rewrite(sql='select id from customers'))
"""


def test_code_mode(oracle: Oracle, tmp_path: Path) -> None:
    tools_offered: list[list[str]] = []
    tool_choices: list[object] = []
    returned: list[str] = []

    def model(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        tools_offered.append([tool.name for tool in info.function_tools])
        tool_choice = dict(info.model_settings or {}).get('tool_choice')
        tool_choices.append(tool_choice)
        returns = [part for message in messages for part in message.parts if isinstance(part, ToolReturnPart)]
        if returns or tool_choice == 'none':
            returned.extend(str(part.content) for part in returns)
            return ModelResponse(parts=[TextPart('summary')])
        return ModelResponse(parts=[ToolCallPart('run_code', {'code': CODE})])

    session = Session(oracle, tmp_path, turns=5)
    library.refresh()

    def run() -> str:
        return attacker.agent.run_sync('attack', model=FunctionModel(model), deps=session).output

    assert run() == 'summary'
    # the file tools are gone: the agent reads the mounted copy and calls `rewrite` from Python
    assert tools_offered == [['run_code'], ['run_code']]
    assert tool_choices == ['auto', 'auto']
    [output] = returned
    assert 'read-only' in output
    assert 'False' in output
    assert 'SELECT customers.id' in output
    assert session.tried == ['accepted: select id from customers']
    assert not (library.PATH / 'written').exists()

    # on the last turn of a round the model may not call `run_code`, so the reply is the summary
    tool_choices.clear()
    session.turns = 1
    assert run() == 'summary'
    assert tool_choices == ['none']
