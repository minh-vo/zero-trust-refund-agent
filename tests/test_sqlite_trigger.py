"""The database enforces the accounting rule even if application code skips the check."""

import sqlite3
import time

import pytest

from shopease_agent.config import load_policy_constants
from shopease_agent.data import load_data
from shopease_agent.ledger import AtomicSqliteLedger, ReservationExpired, to_cents


@pytest.fixture
def ledger(tmp_path):
    d = load_data()
    return AtomicSqliteLedger(tmp_path / "l.db", d.orders, d.refunds, load_policy_constants())


def raw(ledger):
    return sqlite3.connect(ledger.path, isolation_level=None)


def test_direct_over_refund_insert_is_aborted(ledger):
    conn = raw(ledger)
    with pytest.raises(sqlite3.IntegrityError, match="exceed the amount paid"):
        conn.execute("INSERT INTO refunds(refund_id, order_id, customer_id, session_id, "
                     "amount_cents, status, created_at, updated_at) "
                     "VALUES ('X', 'O1041', 'C1002', 'S', 50000, 'issued', 0, 0)")


def test_amounts_cannot_be_edited(ledger):
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw(ledger).execute("UPDATE refunds SET amount_cents=100 WHERE refund_id='R9001'")


def test_rows_cannot_be_deleted(ledger):
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        raw(ledger).execute("DELETE FROM refunds WHERE refund_id='R9001'")


def test_issued_refund_cannot_be_reopened(ledger):
    with pytest.raises(sqlite3.IntegrityError, match="pending to issued or released"):
        raw(ledger).execute("UPDATE refunds SET status='released' WHERE refund_id='R9001'")


def test_stale_reservation_expires_and_cannot_be_paid(ledger):
    ledger.pending_ttl_s = 0.01
    first = ledger.reserve(order_id="O1041", customer_id="C1002", session_id="S",
                           amount_cents=to_cents(200))
    assert first.ok
    time.sleep(0.05)
    # The next reserve() sweeps expired holds, so the budget is free again...
    second = ledger.reserve(order_id="O1041", customer_id="C1002", session_id="S",
                            amount_cents=to_cents(200))
    assert second.ok
    # ...and the abandoned reservation can no longer be paid out.
    with pytest.raises(ReservationExpired):
        ledger.finalize(first.reservation, approved=True)


def test_seed_ledger_is_persisted_once(tmp_path):
    d = load_data()
    policy = load_policy_constants()
    a = AtomicSqliteLedger(tmp_path / "p.db", d.orders, d.refunds, policy)
    assert a.refunded_cents("O1041") == to_cents(180)
    b = AtomicSqliteLedger(tmp_path / "p.db", d.orders, d.refunds, policy)  # reopen
    assert b.refunded_cents("O1041") == to_cents(180)  # not seeded twice
