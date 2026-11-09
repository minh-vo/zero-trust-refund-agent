"""Attack 8.4: the concurrent refund race, run without a model.

Two refund requests for the same order arrive at the same time. That can be the same
customer in two browser tabs, two sessions, or (most simply) one model turn that
emits two parallel `issue_refund_secure` calls, which LangGraph's ToolNode runs on a
thread pool.

The window the race uses is human approval. Reviewers are slow, so to make the timing
deterministic the reviewer here holds every approval until all concurrent requests
have passed through `reserve()`. That is not a test-only hook in the ledger: it is
exactly what happens when the reviewer takes a few seconds to click "approve".
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .context import SecurityContext, start_session
from .hitl import ApprovalRequest
from .ledger import Ledger, LedgerDecision, usd
from .services import Services
from .tools import make_secure_tools


class ReservationGate:
    """Wraps a ledger and counts how many reserve() calls have returned."""

    def __init__(self, inner: Ledger, expected: int) -> None:
        self.inner = inner
        self.name = inner.name
        self.expected = expected
        self._done = 0
        self._cond = threading.Condition()

    def reserve(self, **kwargs: Any) -> LedgerDecision:
        try:
            return self.inner.reserve(**kwargs)
        finally:
            with self._cond:
                self._done += 1
                self._cond.notify_all()

    def wait_for_all_reservations(self, timeout: float = 10.0) -> bool:
        with self._cond:
            return self._cond.wait_for(lambda: self._done >= self.expected, timeout=timeout)

    def __getattr__(self, item: str) -> Any:  # finalize, refunded_cents, ...
        return getattr(self.inner, item)


def slow_reviewer(gate: ReservationGate) -> Callable[[ApprovalRequest], bool]:
    """A reviewer who approves, but only after every concurrent request has been checked."""

    def approve(_: ApprovalRequest) -> bool:
        gate.wait_for_all_reservations()
        return True

    return approve


@dataclass
class RaceResult:
    ledger: str
    order_id: str
    order_value_cents: int
    before_cents: int
    after_cents: int
    responses: list[str]

    @property
    def over_refund_cents(self) -> int:
        return max(0, self.after_cents - self.order_value_cents)

    def summary(self) -> str:
        lines = [f"ledger: {self.ledger}",
                 f"  order {self.order_id} worth {usd(self.order_value_cents)}, "
                 f"{usd(self.before_cents)} already refunded"]
        lines += [f"  request {i}: {r}" for i, r in enumerate(self.responses, 1)]
        lines.append(f"  total refunded now: {usd(self.after_cents)}")
        if self.over_refund_cents:
            lines.append(f"  OVER-REFUNDED BY {usd(self.over_refund_cents)}")
        else:
            lines.append("  within the order value")
        return "\n".join(lines)


def run_concurrent_refunds(svc: Services,
                           requests: list[tuple[str, str, float]]) -> list[str]:
    """Fire every (session_id, order_id, amount_usd) refund at once through the real tools.

    Each request gets its own SecurityContext and tool set, exactly as separate
    conversations (or two tabs on the same session) would.
    """
    gate = ReservationGate(svc.ledger, expected=len(requests))
    original_approver = svc.hitl.approver
    svc.ledger = gate  # type: ignore[assignment]
    svc.hitl.approver = slow_reviewer(gate)
    try:
        calls = []
        for session_id, order_id, amount in requests:
            ctx: SecurityContext = start_session(svc.data, session_id)
            refund = next(t for t in make_secure_tools(ctx, svc)
                          if t.name == "issue_refund_secure")
            calls.append((refund, {"order_id": order_id, "amount_usd": amount}))
        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            return list(pool.map(lambda c: c[0].invoke(c[1]), calls))
    finally:
        svc.ledger = gate.inner  # type: ignore[assignment]
        svc.hitl.approver = original_approver


def run_refund_race(svc: Services, *, order_id: str = "O1041", amount_usd: float = 230.0,
                    sessions: tuple[str, ...] = ("SESS-1001", "SESS-1001")) -> RaceResult:
    """Attack 8.4: two refunds on the same order at the same moment.

    O1041 is worth $612 with $180 already refunded. Two $230 requests each fit the
    $250 per-call cap, and each one alone fits the order. Together they make $640.
    """
    order = svc.data.order(order_id)
    if order is None:
        raise ValueError(f"unknown order {order_id}")
    before = svc.ledger.refunded_cents(order_id)
    responses = run_concurrent_refunds(svc, [(s, order_id, amount_usd) for s in sessions])
    return RaceResult(ledger=svc.ledger.name, order_id=order_id,
                      order_value_cents=round(order["amount_usd"] * 100),
                      before_cents=before, after_cents=svc.ledger.refunded_cents(order_id),
                      responses=responses)
