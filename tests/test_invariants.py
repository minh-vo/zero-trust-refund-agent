"""The four refund invariants, on both ledgers, without any concurrency."""

import pytest

from shopease_agent.ledger import evaluate_invariants, to_cents

POLICY = {"self_service_refund_cap_usd": 250.0, "session_refund_cap_usd": 500.0}


def check(amount, order=612.00, already=180.00, session=0.0):
    return evaluate_invariants(amount_cents=to_cents(amount), order_value_cents=to_cents(order),
                               already_cents=to_cents(already), session_cents=to_cents(session),
                               policy=POLICY)


@pytest.mark.parametrize("amount", [0, -50, -0.01])
def test_non_positive_amounts_are_refused(amount):
    assert not check(amount).ok


def test_per_call_cap():
    assert not check(250.01).ok
    assert check(250.00).ok


def test_cumulative_per_order():
    assert check(432.00 - 250.00).ok
    assert not check(250.00, already=400.00).ok  # 650 > 612


def test_session_cap():
    assert not check(200.00, session=350.00).ok
    assert check(150.00, session=350.00).ok


def test_cents_rounding_is_exact():
    # 0.1 + 0.2 style float error must not let a refund squeak past the order value.
    assert check(0.30, order=100.30, already=100.00).ok
    assert not check(0.31, order=100.30, already=100.00).ok


@pytest.mark.parametrize("ledger", ["memory", "atomic"])
def test_refund_splitting_is_refused_on_the_third_instalment(ledger, make_svc, tools_for, approve):
    """Attack 8.2: $180 + $160 + $150 + $140 = $630 against a $612 order."""
    svc = make_svc(ledger, approver=approve)
    _, t = tools_for(svc)
    out = [t["issue_refund_secure"].invoke({"order_id": "O1041", "amount_usd": a})
           for a in (160, 150, 140)]
    assert out[0].startswith("Refund of $160.00")
    assert out[1].startswith("Refund of $150.00")
    assert out[2].startswith("REFUSED: cumulative refund would reach $630.00")
    assert svc.ledger.refunded_cents("O1041") == to_cents(490)


def test_denied_approval_releases_the_reservation(make_svc, tools_for):
    """A refund the reviewer rejects must not keep eating the budget."""
    svc = make_svc("atomic")  # auto_deny
    _, t = tools_for(svc)
    assert "NOT PROCESSED" in t["issue_refund_secure"].invoke({"order_id": "O1041",
                                                               "amount_usd": 200})
    statuses = [r["status"] for r in svc.ledger.rows("O1041") if r["source"] == "agent"]
    assert statuses == ["released"]
    assert svc.ledger.refunded_cents("O1041") == to_cents(180)
