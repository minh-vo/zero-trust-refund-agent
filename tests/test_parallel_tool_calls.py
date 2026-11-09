"""Attack 8.4 the way it happens in practice: one model turn, two parallel tool calls.

A scripted chat model stands in for Claude so the test runs offline. Everything else is
the real thing: the LangGraph graph, ToolNode's thread pool, the secure tools, the ledger.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from shopease_agent.context import start_session
from shopease_agent.graph import build_agent_graph
from shopease_agent.ledger import to_cents
from shopease_agent.race import ReservationGate, slow_reviewer
from shopease_agent.tools import SECURE_SYSTEM_PROMPT, make_secure_tools


class ScriptedModel(BaseChatModel):
    """Returns the scripted AIMessages in order, then a plain final answer."""

    script: list[AIMessage]

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedModel:
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        msg = self.script.pop(0) if self.script else AIMessage(content="Done.")
        return ChatResult(generations=[ChatGeneration(message=msg)])


def two_parallel_refunds() -> AIMessage:
    return AIMessage(content="", tool_calls=[
        {"name": "issue_refund_secure", "args": {"order_id": "O1041", "amount_usd": 230},
         "id": "call_a", "type": "tool_call"},
        {"name": "issue_refund_secure", "args": {"order_id": "O1041", "amount_usd": 230},
         "id": "call_b", "type": "tool_call"},
    ])


def run_turn(svc) -> list[str]:
    gate = ReservationGate(svc.ledger, expected=2)
    svc.ledger = gate
    svc.hitl.approver = slow_reviewer(gate)
    ctx = start_session(svc.data, "SESS-1001")
    app = build_agent_graph(ScriptedModel(script=[two_parallel_refunds()]),
                            make_secure_tools(ctx, svc), SECURE_SYSTEM_PROMPT)
    out = app.invoke({"messages": [HumanMessage(content="refund both please")]})
    svc.ledger = gate.inner
    return [m.content for m in out["messages"] if m.type == "tool"]


@pytest.mark.parametrize("ledger, expected_total", [("memory", 640), ("atomic", 410)])
def test_parallel_tool_calls_against_each_ledger(make_svc, ledger, expected_total):
    svc = make_svc(ledger)
    results = run_turn(svc)
    assert len(results) == 2
    assert svc.ledger.refunded_cents("O1041") == to_cents(expected_total)
    if ledger == "atomic":
        assert sum(r.startswith("REFUSED") for r in results) == 1
