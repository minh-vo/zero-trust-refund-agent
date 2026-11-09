"""Tamper-evident audit log (notebook Step 10.7).

hash_n = SHA256(entry_n || hash_{n-1}). Editing any past entry breaks the chain from
that point on. The signer and the verifier cover exactly the same bytes: the entry
body without its own `hash` and `prev_hash` fields.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

GENESIS = "GENESIS"


def _hash_entry(body: dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps({"entry": body, "prev": prev_hash}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, event_type: str, detail: dict[str, Any], actor: str = "agent",
               session_id: str | None = None, customer_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            body = {
                "seq": len(self.entries),
                "ts": round(time.time(), 3),
                "session": session_id,
                "customer": customer_id,
                "event_type": event_type,
                "actor": actor,
                "detail": detail,
            }
            entry = {**body, "prev_hash": prev, "hash": _hash_entry(body, prev)}
            self.entries.append(entry)
            return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (intact, index_of_first_bad_entry)."""
        with self._lock:
            prev = GENESIS
            for i, e in enumerate(self.entries):
                body = {k: v for k, v in e.items() if k not in ("hash", "prev_hash")}
                if e.get("prev_hash") != prev or e.get("hash") != _hash_entry(body, prev):
                    return False, i
                prev = e["hash"]
            return True, None

    def of_type(self, *event_types: str) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self.entries if e["event_type"] in event_types]
