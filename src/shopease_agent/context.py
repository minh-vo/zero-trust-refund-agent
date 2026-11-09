"""Caller identity and session binding (notebook Step 10.1).

Every secure tool is built for one `SecurityContext`. The model can read what the tools
tell it, but nothing it emits flows back into this object.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .data import ShopData

AUTH_ORDER = {"unverified": 0, "email_verified": 1, "mfa": 2}


class UnknownSessionError(ValueError):
    """Raised when a conversation cannot be bound to a known session."""


@dataclass
class SecurityContext:
    session_id: str
    customer_id: str
    auth_level: str
    account_status: str
    risk_score: int
    flag_reason: str
    channel: str
    device_trust: str
    # Actions this session has taken, for the sequence-aware fraud rule (10.6).
    _actions: list[str] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def at_least(self, level: str) -> bool:
        return AUTH_ORDER[self.auth_level] >= AUTH_ORDER[level]

    def note(self, action: str) -> None:
        with self._lock:
            self._actions.append(action)

    def did(self, action: str) -> bool:
        with self._lock:
            return action in self._actions


def start_session(data: ShopData, session_id: str) -> SecurityContext:
    """Bind a conversation to an authenticated customer. Fails closed on an unknown session."""
    s = data.session(session_id)
    if s is None:
        raise UnknownSessionError(f"Unknown session {session_id} - refusing to start an unbound agent.")
    c = data.customer(s["customer_id"])
    if c is None:
        raise UnknownSessionError(f"Session {session_id} points at unknown customer {s['customer_id']}.")
    return SecurityContext(
        session_id=s["session_id"],
        customer_id=s["customer_id"],
        auth_level=s["auth_level"],
        account_status=c["account_status"],
        risk_score=int(c["risk_score"]),
        flag_reason=c["flag_reason"] or "",
        channel=s["channel"],
        device_trust=s["device_trust"],
    )
