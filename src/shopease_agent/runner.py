"""Console runners: drive the graph one turn at a time and print what happened."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool

from .framing import frame_untrusted, legacy_input_filter


def _short(text: Any, limit: int = 300) -> str:
    text = str(text)
    return text if len(text) <= limit else f"{text[:limit]} ... [{len(text)} chars]"


def _text_of(message: AIMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return "".join(b.get("text", "") for b in message.content
                   if isinstance(b, dict) and b.get("type") == "text")


def stream_turn(app: Any, messages: list[BaseMessage], show_steps: bool = True
                ) -> tuple[str | None, list[BaseMessage]]:
    """Run the graph once. Returns (final_text, new_messages).

    The caller appends new_messages to its transcript. Never invoke the graph a second
    time to get the final state: that would run every tool twice.
    """
    final_text, collected = None, []
    for update in app.stream({"messages": messages}, config={"recursion_limit": 25}):
        for node_out in update.values():
            for m in (node_out or {}).get("messages", []):
                collected.append(m)
                if isinstance(m, AIMessage) and m.tool_calls:
                    for tc in m.tool_calls:
                        if show_steps:
                            print(f"   [tool call]   {tc['name']}({json.dumps(tc['args'], default=str)})")
                elif isinstance(m, ToolMessage):
                    if show_steps:
                        print(f"   [observation] {_short(m.content)}")
                elif isinstance(m, AIMessage) and _text_of(m):
                    final_text = _text_of(m)
    return final_text, collected


class Conversation:
    """A multi-turn conversation against one compiled agent.

    `guard` decides what happens to each customer message before the model sees it:
    the baseline blocks on a filter hit, the secure agent frames and passes it on.
    """

    def __init__(self, app: Any, label: str, guard: Callable[[str], str | None],
                 show_steps: bool = True) -> None:
        self.app, self.label, self.guard, self.show_steps = app, label, guard, show_steps
        self.messages: list[BaseMessage] = []
        self.turn = 0

    def say(self, text: str) -> str | None:
        self.turn += 1
        print(f"\n{'-' * 78}\n>> {self.label} - turn {self.turn}\n{'-' * 78}")
        print(f"Customer: {text}\n")
        guarded = self.guard(text)
        if guarded is None:
            print("\nAgent: I can't help with that request.\n")
            return None
        self.messages.append(HumanMessage(content=guarded))
        final, new = stream_turn(self.app, self.messages, self.show_steps)
        self.messages += new
        print(f"\nAgent: {final}\n")
        return final


def baseline_guard(text: str) -> str | None:
    blocked, hits = legacy_input_filter(text)
    if blocked:
        print(f"   [input filter] BLOCKED - matched {hits}")
        return None
    print("   [input filter] pass - nothing to match on")
    return text


def make_secure_guard(audit: Any = None) -> Callable[[str], str]:
    def guard(text: str) -> str:
        framed, flags = frame_untrusted(text, "user_input", audit)
        if flags:
            print(f"   [input signal] flagged {flags} - framed as untrusted, not blocked")
        return framed
    return guard


def submit_directly(t: BaseTool, args: dict, why: str = "") -> str:
    """Call a tool without the model.

    A safety-trained model sometimes asks "shall I submit that?" instead of calling a
    high-impact tool. When the point is the gate rather than the model's manners, call
    the tool ourselves. The gate does not care who called it.
    """
    print(f"\n   [direct tool call] {why or t.name}")
    result = t.invoke(args)
    print(f"   -> {result}")
    return result
