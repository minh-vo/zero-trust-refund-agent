"""The ShopEase dataset: customers, orders, the seed refund ledger, and sessions.

`ShopData` wraps the DataFrames behind a lock, because the secure agent can run two
tool calls at the same time (LangGraph's ToolNode executes parallel tool calls on a
thread pool) and pandas is not safe to write from several threads.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from .config import DATA_DIR

FIRST_PARTY_SELLER_ID = "SELLER-FIRSTPARTY"
UPDATABLE_PROFILE_FIELDS = frozenset({"shipping_address", "email", "phone"})


def is_first_party(seller_id: Any) -> bool:
    """True if ShopEase settles the order itself rather than a marketplace seller.

    This is the only place the rule is written down. The authorisation layer and the
    attack narration both call it, so they cannot drift apart.
    """
    return str(seller_id).strip() == FIRST_PARTY_SELLER_ID


def _clean(value: Any) -> Any:
    """NaN -> None so records serialise to JSON cleanly."""
    if isinstance(value, float) and pd.isna(value):
        return None
    return value


@dataclass
class ShopData:
    customers: pd.DataFrame
    orders: pd.DataFrame
    refunds: pd.DataFrame
    sessions: pd.DataFrame
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # ---- reads -------------------------------------------------------------
    def order(self, order_id: str) -> dict | None:
        with self.lock:
            row = self.orders.loc[self.orders.order_id == order_id]
            if row.empty:
                return None
            return {k: _clean(v) for k, v in row.iloc[0].to_dict().items()}

    def customer(self, customer_id: str) -> dict | None:
        with self.lock:
            row = self.customers.loc[self.customers.customer_id == customer_id]
            if row.empty:
                return None
            return {k: _clean(v) for k, v in row.iloc[0].to_dict().items()}

    def session(self, session_id: str) -> dict | None:
        with self.lock:
            row = self.sessions.loc[self.sessions.session_id == session_id]
            if row.empty:
                return None
            return {k: _clean(v) for k, v in row.iloc[0].to_dict().items()}

    def owner_of(self, kind: str | None, record_id: str | None) -> str | None:
        if kind == "order" and record_id:
            o = self.order(record_id)
            return None if o is None else o["customer_id"]
        if kind == "customer" and record_id:
            return record_id if self.customer(record_id) is not None else None
        return None

    def seed_refunded(self, order_id: str) -> float:
        """Refunds already on the books before this run (from refunds.csv)."""
        with self.lock:
            return float(self.refunds.loc[self.refunds.order_id == order_id, "amount_usd"].sum())

    # ---- writes ------------------------------------------------------------
    def update_customer_field(self, customer_id: str, field_name: str, value: str) -> None:
        if field_name not in UPDATABLE_PROFILE_FIELDS:
            raise ValueError(f"field '{field_name}' is not updatable")
        with self.lock:
            self.customers.loc[self.customers.customer_id == customer_id, field_name] = value

    def mark_refund_issued(self, order_id: str) -> None:
        with self.lock:
            self.orders.loc[self.orders.order_id == order_id, "refund_status"] = "Issued"


def load_data(data_dir: Path | str = DATA_DIR) -> ShopData:
    """Read the four CSVs. Each call returns fresh, independent DataFrames."""
    d = Path(data_dir)
    customers = pd.read_csv(d / "customers.csv", dtype={"billing_zip": str})
    orders = pd.read_csv(d / "orders.csv")
    refunds = pd.read_csv(d / "refunds.csv")
    sessions = pd.read_csv(d / "sessions.csv")
    # Profile fields are free text; make the columns object-typed so writes never
    # trip pandas' dtype checks.
    for col in ("shipping_address", "email", "phone", "flag_reason"):
        customers[col] = customers[col].astype("object")
    orders["refund_status"] = orders["refund_status"].astype("object")
    return ShopData(customers=customers, orders=orders, refunds=refunds, sessions=sessions)
