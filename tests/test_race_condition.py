"""Attack 8.4, the reason this repo exists.

The notebook's ledger checks the budget, waits for a human, then writes. Two requests
that wait at the same time were both checked against a ledger containing neither.
The atomic ledger reserves the money inside the same transaction as the check.
"""

from shopease_agent.ledger import to_cents
from shopease_agent.race import run_concurrent_refunds, run_refund_race


def test_notebook_ledger_over_refunds_under_concurrency(make_svc):
    result = run_refund_race(make_svc("memory"))
    assert all(r.startswith("Refund of $230.00") for r in result.responses)
    assert result.after_cents == to_cents(640)
    assert result.over_refund_cents == to_cents(28)


def test_atomic_ledger_refuses_the_second_concurrent_refund(make_svc):
    svc = make_svc("atomic")
    result = run_refund_race(svc)
    issued = [r for r in result.responses if r.startswith("Refund of $230.00")]
    refused = [r for r in result.responses if r.startswith("REFUSED")]
    assert len(issued) == 1 and len(refused) == 1
    assert "cumulative refund would reach $640.00" in refused[0]
    assert result.after_cents == to_cents(410)
    assert svc.audit.verify() == (True, None)


def test_race_across_two_sessions(make_svc):
    """Same customer, two different sessions. Each session's own cap is fine."""
    svc = make_svc("atomic")
    svc.data.sessions.loc[len(svc.data.sessions)] = {
        "session_id": "SESS-2001", "customer_id": "C1002", "auth_level": "email_verified",
        "started_at": "2026-09-28T09:05:00Z", "channel": "mobile_app", "ip_country": "US",
        "device_trust": "trusted"}
    result = run_refund_race(svc, sessions=("SESS-1001", "SESS-2001"))
    assert result.over_refund_cents == 0


def test_session_cap_race(make_svc):
    """Three $200 refunds on three different orders, all at once, against a $500 cap."""
    requests = [("SESS-1001", o, 200.00) for o in ("O1002", "O1122", "O1201")]

    memory = make_svc("memory")
    run_concurrent_refunds(memory, requests)
    assert memory.ledger.session_issued_cents("SESS-1001") == to_cents(600)

    atomic = make_svc("atomic")
    out = run_concurrent_refunds(atomic, requests)
    assert atomic.ledger.session_issued_cents("SESS-1001") == to_cents(400)
    assert sum("per-session cap" in r for r in out) == 1


def test_many_concurrent_requests_never_exceed_the_order(make_svc):
    """Ten $50 requests race for the $432 left on O1041; at most eight can fit."""
    svc = make_svc("atomic")
    run_concurrent_refunds(svc, [("SESS-1001", "O1041", 50.00)] * 10)
    assert svc.ledger.refunded_cents("O1041") <= to_cents(612)
    assert svc.ledger.session_issued_cents("SESS-1001") <= to_cents(500)
