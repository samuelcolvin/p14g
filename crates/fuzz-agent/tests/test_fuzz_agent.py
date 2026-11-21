from __future__ import annotations

import asyncio
from pathlib import Path

from fuzz_agent.attacker import Session
from fuzz_agent.judge import Judge
from fuzz_agent.oracle import Oracle
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
