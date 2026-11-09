"""The atomic refund ledger. This is the improvement over the notebook.

Three things change compared with `InMemoryLedger`:

1. The check and the write happen in one transaction. `reserve()` opens
   `BEGIN IMMEDIATE`, which takes SQLite's write lock before reading. A second
   reserve() on any thread or process waits for the first to commit, and then sees
   its row.

2. The money is counted from the moment it is reserved, not from the moment it is
   paid. A reservation is a `pending` row, inserted *before* the human reviewer is
   asked. Both budgets (per order and per session) count pending + issued rows, so
   a refund sitting in the approval queue already uses up its share. `finalize()`
   then flips the row to `issued` or `released`.

3. The database refuses to break the accounting rule even if the Python is wrong.
   A BEFORE INSERT trigger aborts any row that would push an order's pending + issued
   total past what the customer paid. Two more triggers make rows effectively
   append-only: amounts can't be edited, and a row can only leave `pending` once.

Pending rows older than `pending_ttl_s` are released at the start of the next
reserve(), so an abandoned approval cannot hold a budget forever. finalize() on an
expired reservation raises ReservationExpired instead of paying.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pandas as pd

from .base import (
    LedgerDecision,
    Reservation,
    ReservationExpired,
    evaluate_invariants,
    to_cents,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS orders (
    order_id     TEXT PRIMARY KEY,
    customer_id  TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0)
);

CREATE TABLE IF NOT EXISTS refunds (
    refund_id    TEXT PRIMARY KEY,
    order_id     TEXT NOT NULL REFERENCES orders(order_id),
    customer_id  TEXT NOT NULL,
    session_id   TEXT,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    status       TEXT NOT NULL CHECK (status IN ('pending', 'issued', 'released')),
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    source       TEXT NOT NULL DEFAULT 'agent'
);

CREATE INDEX IF NOT EXISTS refunds_by_order   ON refunds(order_id, status);
CREATE INDEX IF NOT EXISTS refunds_by_session ON refunds(session_id, status);

-- The accounting identity, enforced by the database itself.
CREATE TRIGGER IF NOT EXISTS refunds_never_exceed_order
BEFORE INSERT ON refunds
WHEN NEW.status IN ('pending', 'issued')
 AND (SELECT COALESCE(SUM(amount_cents), 0) FROM refunds
       WHERE order_id = NEW.order_id AND status IN ('pending', 'issued'))
     + NEW.amount_cents
     > (SELECT amount_cents FROM orders WHERE order_id = NEW.order_id)
BEGIN
    SELECT RAISE(ABORT, 'refund would exceed the amount paid for this order');
END;

-- A row's amount is fixed once written.
CREATE TRIGGER IF NOT EXISTS refunds_amount_immutable
BEFORE UPDATE OF amount_cents, order_id, session_id ON refunds
BEGIN
    SELECT RAISE(ABORT, 'refund rows are append-only');
END;

-- pending -> issued | released, and nothing else.
CREATE TRIGGER IF NOT EXISTS refunds_status_one_way
BEFORE UPDATE OF status ON refunds
WHEN OLD.status != 'pending' OR NEW.status NOT IN ('issued', 'released')
BEGIN
    SELECT RAISE(ABORT, 'refund status can only move from pending to issued or released');
END;

CREATE TRIGGER IF NOT EXISTS refunds_no_delete
BEFORE DELETE ON refunds
BEGIN
    SELECT RAISE(ABORT, 'refund rows are append-only');
END;
"""

COUNTED = "('pending', 'issued')"


class AtomicSqliteLedger:
    name = "atomic SQLite"

    def __init__(self, path: Path | str, orders: pd.DataFrame, refunds: pd.DataFrame,
                 policy: dict[str, Any], pending_ttl_s: float = 900.0):
        if str(path) == ":memory:":
            raise ValueError("use a file path: an in-memory SQLite DB is not shared across threads")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.pending_ttl_s = pending_ttl_s
        self._local = threading.local()
        with self._conn() as conn:
            conn.executescript(SCHEMA)
        self._seed(orders, refunds)

    # ---- connections -------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        """One connection per thread. Autocommit mode; transactions are explicit."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                   check_same_thread=True)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    def _seed(self, orders: pd.DataFrame, refunds: pd.DataFrame) -> None:
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
                conn.executemany(
                    "INSERT INTO orders(order_id, customer_id, amount_cents) VALUES (?, ?, ?)",
                    [(r.order_id, r.customer_id, to_cents(r.amount_usd))
                     for r in orders.itertuples()])
                now = time.time()
                conn.executemany(
                    "INSERT INTO refunds(refund_id, order_id, customer_id, session_id, "
                    "amount_cents, status, created_at, updated_at, source) "
                    "VALUES (?, ?, ?, ?, ?, 'issued', ?, ?, 'seed')",
                    [(r.refund_id, r.order_id, r.customer_id,
                      None if pd.isna(r.session_id) else r.session_id,
                      to_cents(r.amount_usd), now, now)
                     for r in refunds.itertuples()])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ---- the two-step refund ------------------------------------------------
    def reserve(self, *, order_id: str, customer_id: str, session_id: str,
                amount_cents: int) -> LedgerDecision:
        conn = self._conn()
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")  # take the write lock BEFORE reading
        try:
            conn.execute("UPDATE refunds SET status='released', updated_at=? "
                         "WHERE status='pending' AND created_at < ?",
                         (now, now - self.pending_ttl_s))

            row = conn.execute("SELECT amount_cents FROM orders WHERE order_id=?",
                               (order_id,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return LedgerDecision(False, f"order {order_id} not found")

            already = conn.execute(
                f"SELECT COALESCE(SUM(amount_cents),0) FROM refunds "
                f"WHERE order_id=? AND status IN {COUNTED}", (order_id,)).fetchone()[0]
            session = conn.execute(
                f"SELECT COALESCE(SUM(amount_cents),0) FROM refunds "
                f"WHERE session_id=? AND status IN {COUNTED}", (session_id,)).fetchone()[0]

            result = evaluate_invariants(amount_cents=amount_cents, order_value_cents=row[0],
                                         already_cents=already, session_cents=session,
                                         policy=self.policy)
            if not result.ok:
                conn.execute("ROLLBACK")
                return LedgerDecision(False, result.reason)

            rid = f"R-{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO refunds(refund_id, order_id, customer_id, session_id, amount_cents, "
                "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (rid, order_id, customer_id, session_id, amount_cents, now, now))
            conn.execute("COMMIT")
            return LedgerDecision(True, result.reason,
                                  Reservation(rid, order_id, customer_id, session_id, amount_cents))
        except sqlite3.IntegrityError as exc:
            conn.execute("ROLLBACK")
            return LedgerDecision(False, f"refused by the database: {exc}")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def finalize(self, reservation: Reservation, approved: bool) -> None:
        conn = self._conn()
        cur = conn.execute(
            "UPDATE refunds SET status=?, updated_at=? WHERE refund_id=? AND status='pending'",
            ("issued" if approved else "released", time.time(), reservation.reservation_id))
        if cur.rowcount != 1:
            raise ReservationExpired(
                f"reservation {reservation.reservation_id} is no longer pending")

    # ---- reads --------------------------------------------------------------
    def refunded_cents(self, order_id: str) -> int:
        return self._conn().execute(
            "SELECT COALESCE(SUM(amount_cents),0) FROM refunds "
            "WHERE order_id=? AND status='issued'", (order_id,)).fetchone()[0]

    def session_issued_cents(self, session_id: str) -> int:
        return self._conn().execute(
            "SELECT COALESCE(SUM(amount_cents),0) FROM refunds "
            "WHERE session_id=? AND status='issued'", (session_id,)).fetchone()[0]

    def rows(self, order_id: str | None = None) -> list[dict[str, Any]]:
        conn = self._conn()
        conn.row_factory = sqlite3.Row
        try:
            q = "SELECT * FROM refunds" + (" WHERE order_id=?" if order_id else "") + \
                " ORDER BY created_at, refund_id"
            return [dict(r) for r in conn.execute(q, (order_id,) if order_id else ())]
        finally:
            conn.row_factory = None
