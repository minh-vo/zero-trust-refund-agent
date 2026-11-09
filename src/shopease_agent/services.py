"""Everything the secure tools need, in one object instead of module globals.

The notebook kept the session, the DataFrames and the ledger in globals. That is fine
for one conversation in one kernel, but it makes two concurrent sessions impossible
to even express. Here each conversation gets its own `SecurityContext`, and they all
share one `Services`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import APPROVED_CORPUS, DATA_DIR, POLICY_PDF_CLEAN, STATE_DIR, load_policy_constants
from .data import ShopData, load_data
from .hitl import ApprovalQueue, Approver, auto_deny
from .ledger import AtomicSqliteLedger, InMemoryLedger, Ledger
from .scopes import ToolScope, build_tool_scopes


@dataclass
class Effects:
    """Ground truth for scoring: what actually changed, never what the agent said."""

    refunds: list[dict[str, Any]] = field(default_factory=list)
    profile_writes: list[dict[str, Any]] = field(default_factory=list)
    records_read: list[dict[str, Any]] = field(default_factory=list)
    emails_sent: list[dict[str, Any]] = field(default_factory=list)
    denials: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, kind: str, item: dict[str, Any]) -> None:
        with self._lock:
            getattr(self, kind).append(item)

    def reset(self) -> None:
        with self._lock:
            for kind in ("refunds", "profile_writes", "records_read", "emails_sent", "denials"):
                getattr(self, kind).clear()


@dataclass
class Services:
    data: ShopData
    policy: dict[str, Any]
    scopes: dict[str, ToolScope]
    ledger: Ledger
    audit: AuditLog
    hitl: ApprovalQueue
    manifest: dict[str, str]
    knowledge: Any = None  # a verified vector store, or None (answers come from constants)
    effects: Effects = field(default_factory=Effects)


def build_services(ledger: str = "atomic", *, data_dir: Path | str = DATA_DIR,
                   db_path: Path | str | None = None, approver: Approver = auto_deny,
                   with_knowledge: bool = False, verbose_hitl: bool = False,
                   fresh_db: bool = True) -> Services:
    """Wire up a fresh set of services.

    ledger="atomic" uses AtomicSqliteLedger (the improvement); ledger="memory" uses the
    notebook's check-then-write ledger, for comparison.
    """
    data = load_data(data_dir)
    policy = load_policy_constants(data_dir)
    audit = AuditLog()

    if ledger == "atomic":
        path = Path(db_path) if db_path else STATE_DIR / "ledger.db"
        if fresh_db:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{path}{suffix}").unlink(missing_ok=True)
        led: Ledger = AtomicSqliteLedger(path, data.orders, data.refunds, policy)
    elif ledger == "memory":
        led = InMemoryLedger(data.orders, data.refunds, policy)
    else:
        raise ValueError(f"unknown ledger '{ledger}' (use 'atomic' or 'memory')")

    svc = Services(data=data, policy=policy, scopes=build_tool_scopes(policy), ledger=led,
                   audit=audit, hitl=ApprovalQueue(approver, audit, verbose=verbose_hitl),
                   manifest=dict(APPROVED_CORPUS))
    if with_knowledge:
        from .corpus import CorpusIntegrityError, build_verified_vectorstore

        try:
            svc.knowledge = build_verified_vectorstore(Path(data_dir) / POLICY_PDF_CLEAN,
                                                       svc.manifest, audit)
        except CorpusIntegrityError:
            svc.knowledge = None  # fail closed: policy answers come from the constants only
    return svc
