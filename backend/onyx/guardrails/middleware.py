"""
Guardrail middleware using Llama Guard via LiteLLM.

Replaces the previous regex-based guardrails with LLM-based
content classification for both input and output filtering.
"""

import os

from fastapi import HTTPException

from onyx.guardrails.llama_guard import LlamaGuard, LlamaGuardResult
from onyx.utils.logger import setup_logger

logger = setup_logger()

_REJECTION_MESSAGE = (
    "I'm sorry, but I cannot process this request as it may involve "
    "sensitive information or violates security policies. "
    "Please rephrase your question or contact an administrator."
)


class GuardrailViolationError(HTTPException):
    """Raised when a guardrail blocks a message (input or output)."""

    def __init__(self, detail: str = _REJECTION_MESSAGE) -> None:
        super().__init__(status_code=422, detail=detail)


# ---------------------------------------------------------------------------
# Singleton Llama Guard instance
# ---------------------------------------------------------------------------

_llama_guard_instance: LlamaGuard | None = None


def _get_llama_guard() -> LlamaGuard:
    global _llama_guard_instance
    if _llama_guard_instance is None:
        from onyx.configs.chat_configs import (
            LLAMA_GUARD_API_BASE,
            LLAMA_GUARD_API_KEY,
            LLAMA_GUARD_MODEL,
        )

        _llama_guard_instance = LlamaGuard(
            model=LLAMA_GUARD_MODEL,
            api_key=LLAMA_GUARD_API_KEY or None,
            api_base=LLAMA_GUARD_API_BASE,
        )
    return _llama_guard_instance


# ---------------------------------------------------------------------------
# Public convenience functions (same signatures used by chat_backend.py)
# ---------------------------------------------------------------------------


def apply_input_guardrail(text: str) -> tuple[bool, str]:
    """
    Check user input for safety using Llama Guard.

    Returns:
        (is_safe, rejection_message). If safe, rejection_message is empty.
    """
    enabled = os.environ.get("GUARDRAILS_ENABLED", "true").lower() == "true"
    if not enabled or not text:
        return True, ""

    guard = _get_llama_guard()
    result: LlamaGuardResult = guard.check_input(text)

    if not result.safe:
        logger.warning(
            "Input guardrail triggered – categories: %s",
            result.violated_categories,
        )
        return False, _REJECTION_MESSAGE

    return True, ""


def apply_output_guardrail(user_message: str, assistant_message: str) -> tuple[bool, str]:
    """
    Check assistant output for safety using Llama Guard.

    Returns:
        (is_safe, filtered_or_blocked_message).
        If safe, returns (True, assistant_message) unchanged.
        If unsafe, returns (False, blocked_message).
    """
    enabled = os.environ.get("GUARDRAILS_ENABLED", "true").lower() == "true"
    if not enabled or not assistant_message:
        return True, assistant_message

    guard = _get_llama_guard()
    result: LlamaGuardResult = guard.check_output(user_message, assistant_message)

    if not result.safe:
        logger.warning(
            "Output guardrail triggered – categories: %s",
            result.violated_categories,
        )
        return False, _REJECTION_MESSAGE

    return True, assistant_message
