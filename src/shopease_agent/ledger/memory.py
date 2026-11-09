"""The notebook's ledger, ported faithfully. Kept here as the vulnerable reference.

In the notebook, `issue_refund_secure` does:

    check_refund_invariants(...)   # read the ledger
    require_human_approval(...)    # wait for a person
    REFUND_LEDGER.append(...)      # write the ledger

`reserve()` below is that first line and `finalize()` is the last one. Nothing is held
in between, so two requests that are both waiting on a reviewer were both checked
against a ledger that contained neither of them. Each individual read and write is
locked; the bug is that the check and the write are two separate steps.
"""

from __future__ import annotations

import itertools
import threading
from typing import Any

import pandas as pd

from .base import LedgerDecision, Reservation, evaluate_invariants, to_cents


class InMemoryLedger:
    name = "in-memory (notebook)"

    def __init__(self, orders: pd.DataFrame, refunds: pd.DataFrame, policy: dict[str, Any]):
        self.policy = policy
        self._order_value = {r.order_id: to_cents(r.amount_usd) for r in orders.itertuples()}
        self._rows: list[dict[str, Any]] = [
            {"refund_id": r.refund_id, "order_id": r.order_id, "customer_id": r.customer_id,
             "session_id": None if pd.isna(r.session_id) else r.session_id,
             "amount_cents": to_cents(r.amount_usd)}
            for r in refunds.itertuples()
        ]
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def reserve(self, *, order_id: str, customer_id: str, session_id: str,
                amount_cents: int) -> LedgerDecision:
        if order_id not in self._order_value:
            return LedgerDecision(False, f"order {order_id} not found")
        with self._lock:
            already = sum(r["amount_cents"] for r in self._rows if r["order_id"] == order_id)
            session = sum(r["amount_cents"] for r in self._rows if r["session_id"] == session_id)
            rid = f"MEM-{next(self._ids)}"
        result = evaluate_invariants(amount_cents=amount_cents,
                                     order_value_cents=self._order_value[order_id],
                                     already_cents=already, session_cents=session,
                                     policy=self.policy)
        if not result.ok:
            return LedgerDecision(False, result.reason)
        # Nothing is recorded yet. That is the gap.
        return LedgerDecision(True, result.reason,
                              Reservation(rid, order_id, customer_id, session_id, amount_cents))

    def finalize(self, reservation: Reservation, approved: bool) -> None:
        if not approved:
            return
        with self._lock:
            self._rows.append({"refund_id": reservation.reservation_id,
                               "order_id": reservation.order_id,
                               "customer_id": reservation.customer_id,
                               "session_id": reservation.session_id,
                               "amount_cents": reservation.amount_cents})

    def refunded_cents(self, order_id: str) -> int:
        with self._lock:
            return sum(r["amount_cents"] for r in self._rows if r["order_id"] == order_id)

    def session_issued_cents(self, session_id: str) -> int:
        with self._lock:
            return sum(r["amount_cents"] for r in self._rows if r["session_id"] == session_id)
