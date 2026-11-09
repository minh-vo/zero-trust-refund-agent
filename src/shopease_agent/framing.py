"""The content filter, and its demoted form as a framing signal.

The baseline agent uses `legacy_input_filter` as a gate (notebook Step 5). The secure
agent keeps the same patterns but only uses them to label text and write telemetry
(notebook Step 10.3). Nothing downstream reads the verdict.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .audit import AuditLog

LEGACY_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous\s+|prior\s+|the\s+)?(instructions|rules)",
    r"disregard\s+(all\s+|any\s+)?(previous\s+|prior\s+|the\s+)?(\$?\d+\s+)?"
    r"(instructions|policy|policies|cap|limit)",
    r"system\s+(note|override|instruction|prompt)",
    r"you\s+are\s+(now|no\s+longer)",
    r"do\s+not\s+mention\s+this",
    r"new\s+(instructions|rules|persona)",
    r"developer\s+mode",
    r"jailbreak",
]


def legacy_input_filter(text: str) -> tuple[bool, list[str]]:
    """Return (blocked, matched_patterns). A keyword stand-in for an injection classifier."""
    lowered = text.lower()
    hits = [p for p in LEGACY_INJECTION_PATTERNS if re.search(p, lowered)]
    return bool(hits), hits


def frame_untrusted(text: str, source: str, audit: AuditLog | None = None) -> tuple[str, list[str]]:
    """Wrap untrusted text in explicit markers and flag instruction-like language.

    This never blocks. It gives the model a clear label and gives us telemetry.
    """
    _, flags = legacy_input_filter(text)
    if flags and audit is not None:
        audit.append("untrusted_content_flagged",
                     {"source": source, "patterns": flags, "excerpt": text[:180]},
                     actor="guardrail")
    banner = f"BEGIN UNTRUSTED CONTENT (source={source}"
    if flags:
        banner += f"; WARNING: instruction-like language detected: {flags}"
    banner += ")"
    return f"[{banner}]\n{text}\n[END UNTRUSTED CONTENT (source={source})]", flags
