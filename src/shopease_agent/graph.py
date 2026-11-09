"""A plain ReAct loop: agent node <-> ToolNode, built by hand so it matches the diagram."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode, tools_condition


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]


def build_agent_graph(llm: Any, tools: list[BaseTool], system_prompt: str) -> Any:
    """Compile the agent. The system prompt is prepended on every call, never stored in
    state, so a long transcript cannot push it out or duplicate it."""
    llm_with_tools = llm.bind_tools(tools)

    def agent_node(state: AgentState) -> dict:
        msgs = [SystemMessage(content=system_prompt), *state["messages"]]
        return {"messages": [llm_with_tools.invoke(msgs)]}

    g = StateGraph(AgentState)
    g.add_node("agent", agent_node)
    g.add_node("tools", ToolNode(tools))  # runs parallel tool calls on a thread pool
    g.set_entry_point("agent")
    g.add_conditional_edges("agent", tools_condition)
    g.add_edge("tools", "agent")
    return g.compile()
