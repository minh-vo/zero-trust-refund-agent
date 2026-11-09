"""Human-in-the-loop approval for high-impact actions (notebook Step 10.6).

The approver is a plain callable so the queue works in tests, scripts and a real
review UI alike. The default denies: if nobody is on duty, money does not move.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit import AuditLog


@dataclass
class ApprovalRequest:
    tool: str
    args: dict[str, Any]
    risk_note: str
    session_id: str
    customer_id: str
    ts: float = field(default_factory=time.time)
    approved: bool | None = None


Approver = Callable[[ApprovalRequest], bool]


def auto_deny(_: ApprovalRequest) -> bool:
    return False


def auto_approve(_: ApprovalRequest) -> bool:
    return True


def interactive(req: ApprovalRequest) -> bool:
    print(f"\n   *** HUMAN APPROVAL REQUIRED *** {req.tool} {req.args}")
    if req.risk_note:
        print(f"       risk: {req.risk_note}")
    return input("       approve? [y/N]: ").strip().lower() == "y"


class ApprovalQueue:
    def __init__(self, approver: Approver = auto_deny, audit: AuditLog | None = None,
                 verbose: bool = False) -> None:
        self.approver = approver
        self.audit = audit
        self.verbose = verbose
        self.items: list[ApprovalRequest] = []
        self._lock = threading.Lock()

    def request(self, req: ApprovalRequest) -> bool:
        with self._lock:
            self.items.append(req)
        try:
            approved = bool(self.approver(req))
        except Exception:
            approved = False  # a broken reviewer integration fails closed
        req.approved = approved
        if self.verbose:
            note = f"  risk: {req.risk_note}" if req.risk_note else ""
            print(f"   [human approval] {req.tool} {req.args} -> "
                  f"{'APPROVED' if approved else 'DENIED'}{note}")
        if self.audit is not None:
            self.audit.append("hitl_decision",
                              {"tool": req.tool, "args": req.args, "approved": approved,
                               "risk_note": req.risk_note},
                              actor="human_reviewer", session_id=req.session_id,
                              customer_id=req.customer_id)
        return approved
