"""What every refund ledger has to provide, and the invariants both ledgers share.

A refund is a two-step operation:

    reserve(...)   -> decide whether this refund fits the budgets
    finalize(...)  -> after the human decides, make it real or drop it

The notebook's ledger and the atomic ledger implement the same interface. The
difference is *when* the money is counted, and that difference is the whole of
attack 8.4.

All amounts are integer cents. Floats are only used at the edges for display.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Protocol


def to_cents(amount_usd: float | int | str | Decimal) -> int:
    return int((Decimal(str(amount_usd)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def usd(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    return f"{sign}${abs(cents) / 100:,.2f}"


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    order_id: str
    customer_id: str
    session_id: str
    amount_cents: int


@dataclass(frozen=True)
class LedgerDecision:
    ok: bool
    reason: str
    reservation: Reservation | None = None


class ReservationExpired(Exception):
    """finalize() was called on a reservation that is no longer pending."""


@dataclass(frozen=True)
class InvariantResult:
    ok: bool
    reason: str = "all refund invariants satisfied"


def evaluate_invariants(*, amount_cents: int, order_value_cents: int, already_cents: int,
                        session_cents: int, policy: dict[str, Any]) -> InvariantResult:
    """The four budget rules from notebook Step 10.5. Pure arithmetic, no model."""
    if amount_cents <= 0:
        return InvariantResult(False, f"{usd(amount_cents)} is not a positive refund amount")

    per_call = to_cents(policy["self_service_refund_cap_usd"])
    if amount_cents > per_call:
        return InvariantResult(False, f"{usd(amount_cents)} exceeds the {usd(per_call)} "
                                      "per-refund self-service cap")

    if already_cents + amount_cents > order_value_cents:
        return InvariantResult(
            False,
            f"cumulative refund would reach {usd(already_cents + amount_cents)} against an order "
            f"worth {usd(order_value_cents)} ({usd(already_cents)} already refunded or reserved) "
            "- an order can never refund more than the customer paid")

    session_cap = to_cents(policy["session_refund_cap_usd"])
    if session_cents + amount_cents > session_cap:
        return InvariantResult(
            False,
            f"session total would reach {usd(session_cents + amount_cents)}, over the "
            f"{usd(session_cap)} per-session cap")

    return InvariantResult(True)


class Ledger(Protocol):
    name: str

    def reserve(self, *, order_id: str, customer_id: str, session_id: str,
                amount_cents: int) -> LedgerDecision: ...

    def finalize(self, reservation: Reservation, approved: bool) -> None: ...

    def refunded_cents(self, order_id: str) -> int:
        """Money actually paid out on this order (issued only)."""
        ...

    def session_issued_cents(self, session_id: str) -> int: ...
