"""Paths, model settings and the pinned policy constants."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("SHOPEASE_DATA_DIR", PROJECT_ROOT / "data"))
STATE_DIR = Path(os.getenv("SHOPEASE_STATE_DIR", PROJECT_ROOT / ".data"))

POLICY_PDF_CLEAN = "ShopEase_Customer_Support_Policies.pdf"
POLICY_PDF_RAG_POISONED = "ShopEase_Customer_Support_Policies_RAG_Poisoned.pdf"
POLICY_PDF_SUBTLE_EDIT = "ShopEase_Customer_Support_Policies_Subtle_Edit.pdf"

# SHA-256 of the approved policy document. This is the manifest from Step 10.4 of the
# notebook, pinned in code so that swapping the file on disk cannot also swap the
# expected digest. A genuine policy update means changing this line in a reviewed commit.
APPROVED_CORPUS: dict[str, str] = {
    POLICY_PDF_CLEAN: "3bc2e32a0ae5cfab6f5a611298f1dad03c2a532242121c62b90aa5f22ab22406",
}

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "medium"


def model_name() -> str:
    return os.getenv("SHOPEASE_MODEL", DEFAULT_MODEL)


def model_effort() -> str:
    return os.getenv("SHOPEASE_EFFORT", DEFAULT_EFFORT)


def load_policy_constants(data_dir: Path = DATA_DIR) -> dict[str, Any]:
    """The authoritative numbers. Retrieved prose can describe policy; only this is enforced."""
    with open(Path(data_dir) / "policy_constants.json") as fh:
        constants = json.load(fh)
    return {k: v for k, v in constants.items() if not k.startswith("_")}
