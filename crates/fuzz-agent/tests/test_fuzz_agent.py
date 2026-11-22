from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fuzz_agent.__main__ import usable_summary
from fuzz_agent.attacker import (
    Session,
    last_turn_without_tools,
    turn_instructions,
)
from fuzz_agent.judge import Judge
from fuzz_agent.oracle import Oracle
from fuzz_agent.worker import Worker
from pydantic_ai.models.decision import (
    DecisionModel,
    DecisionModelSettings,
    DecisionRequest,
    DecisionResponse,
    NoulAnswer,
    NoulQuestion,
)
from pydantic_ai.providers import InterfaceClient


class StubDecisionModel(DecisionModel[InterfaceClient]):
    def __init__(self) -> None:
        super().__init__()
        self.request_seen: DecisionRequest | None = None

    @property
    def model_name(self) -> str:
        return 'jev-stub'

    @property
    def system(self) -> str:
        return 'test'

    async def decide(self, request: DecisionRequest, model_settings: DecisionModelSettings) -> DecisionResponse:
        self.request_seen = request
        return DecisionResponse(
            answers={name: NoulAnswer(noul=0.9 if name == 'harmful_call' else 0.1) for name in request.questions},
            model_name='jev-stub-1.0',
        )


def test_oracle_without_database(tmp_path: Path) -> None:
    oracle = Oracle(None)
    try:
        _check_oracle_without_database(oracle, tmp_path)
    finally:
        oracle.close()


def _check_oracle_without_database(oracle: Oracle, tmp_path: Path) -> None:

    allowed = oracle.attempt('select id, name from customers')
    assert allowed.output == 'SELECT customers.id, customers.name\nFROM public.customers\nLIMIT 50'
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

    session = Session(oracle, None, tmp_path)
    assert 'crates/p14g/src/check.rs' in session.files
    assert '.claude/skills' not in session.files


def test_decision_model_judge() -> None:
    model = StubDecisionModel()
    judge = Judge(model, 0.5)

    answered_by, flags = asyncio.run(judge.flags('select 1', 'SELECT 1'))

    assert answered_by == 'jev-stub-1.0'
    assert flags == ['harmful_call (confidence 0.80)']
    assert model.request_seen is not None
    assert len(model.request_seen.questions) == 5
    question = model.request_seen.questions['harmful_call']
    assert isinstance(question, NoulQuestion)
    assert question.criteria is not None
    assert 'outside `policy.functions`' in str(question.criteria.true)


def test_hang_is_a_finding_and_the_worker_restarts() -> None:
    from handlers import rewrite_unless_marked

    oracle = Oracle(None, worker=Worker(rewrite_unless_marked, timeout=1))
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
