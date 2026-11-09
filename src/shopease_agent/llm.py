"""The chat model. Claude through langchain-anthropic.

The security controls do not depend on which model is used. Swap SHOPEASE_MODEL to
compare models; every gate behaves the same because none of them asks the model.
"""

from __future__ import annotations

import os

from langchain_anthropic import ChatAnthropic

from .config import model_effort, model_name

# If a safety classifier declines a turn, the API retries it on a suitable fallback
# model instead of returning a refusal. Set SHOPEASE_FALLBACKS=0 to turn it off.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


def make_llm() -> ChatAnthropic:
    kwargs: dict = {}
    if os.getenv("SHOPEASE_FALLBACKS", "1") != "0":
        kwargs["betas"] = [FALLBACK_BETA]
        kwargs["model_kwargs"] = {"fallbacks": "default"}
    return ChatAnthropic(
        model=model_name(),
        max_tokens=16000,
        effort=model_effort(),
        **kwargs,
    )
