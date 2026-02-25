"""
Guardrail middleware for LLM request/response processing.

This middleware can be integrated into the chat pipeline to filter
both input and output for security concerns.
"""

import os
from typing import Generator, TypeVar

from onyx.guardrails.config import GuardrailConfig
from onyx.guardrails.input_filter import InputGuardrail, InputFilterResult
from onyx.guardrails.output_filter import OutputGuardrail, FilterResult
from onyx.utils.logger import setup_logger

logger = setup_logger()

T = TypeVar("T")


class GuardrailMiddleware:
    """
    Middleware for applying guardrails to LLM interactions.

    This class provides methods to:
    - Filter user input before sending to LLM
    - Filter LLM output before returning to user
    - Stream-aware filtering for real-time responses

    Usage:
        middleware = GuardrailMiddleware()

        # Check input
        input_result = middleware.check_input(user_message)
        if not input_result.is_safe:
            return "I cannot process that request."

        # Filter output
        output_result = middleware.filter_output(llm_response)
        return output_result.filtered_text
    """

    def __init__(self, config: GuardrailConfig | None = None):
        """
        Initialize the middleware.

        Args:
            config: Optional configuration. Uses default if not provided.
        """
        self.config = config or GuardrailConfig()

        # Check if guardrails are enabled via environment
        self.enabled = os.environ.get("GUARDRAILS_ENABLED", "true").lower() == "true"

        self.input_guardrail = InputGuardrail(self.config)
        self.output_guardrail = OutputGuardrail(self.config)

    def check_input(self, text: str) -> InputFilterResult:
        """
        Check user input for security concerns.

        Args:
            text: The user input to check.

        Returns:
            InputFilterResult with safety assessment.
        """
        if not self.enabled:
            return InputFilterResult(
                original_text=text,
                is_safe=True,
                injection_attempts=[],
                risk_level="none"
            )

        return self.input_guardrail.check_input(text)

    def filter_output(self, text: str) -> FilterResult:
        """
        Filter LLM output for sensitive information.

        Args:
            text: The LLM output to filter.

        Returns:
            FilterResult with filtered text.
        """
        if not self.enabled:
            return FilterResult(
                original_text=text,
                filtered_text=text,
                was_modified=False,
                was_blocked=False,
                violations=[]
            )

        return self.output_guardrail.filter_response(text)

    def filter_stream(
        self,
        stream: Generator[str, None, None],
        buffer_size: int = 100
    ) -> Generator[str, None, None]:
        """
        Filter a streaming LLM response.

        This method buffers tokens to check for patterns that might
        span multiple chunks, while still providing real-time output.

        Args:
            stream: Generator yielding response chunks.
            buffer_size: Number of characters to buffer for pattern matching.

        Yields:
            Filtered response chunks.
        """
        if not self.enabled:
            yield from stream
            return

        buffer = ""

        for chunk in stream:
            buffer += chunk

            # If buffer is large enough, process and yield
            if len(buffer) >= buffer_size:
                # Keep the last buffer_size chars for pattern matching across chunks
                to_yield = buffer[:-buffer_size]
                buffer = buffer[-buffer_size:]

                if to_yield:
                    result = self.output_guardrail.filter_response(to_yield)
                    if result.was_blocked:
                        logger.warning("Stream blocked due to guardrail violation")
                        yield "[Response blocked due to security policy]"
                        return
                    yield result.filtered_text

        # Process remaining buffer
        if buffer:
            result = self.output_guardrail.filter_response(buffer)
            if result.was_blocked:
                yield "[Response blocked due to security policy]"
            else:
                yield result.filtered_text

    def get_blocked_response(self, reason: str = "security") -> str:
        """
        Get a standard blocked response message.

        Args:
            reason: The reason for blocking (for logging).

        Returns:
            User-friendly blocked message.
        """
        logger.warning(f"Response blocked: {reason}")
        return (
            "I'm sorry, but I cannot process this request as it may involve "
            "sensitive information or violates security policies. "
            "Please rephrase your question or contact an administrator."
        )

    def get_injection_response(self) -> str:
        """
        Get a standard response for detected prompt injection.

        Returns:
            User-friendly injection detection message.
        """
        return (
            "I noticed your message contains patterns that could be interpreted "
            "as an attempt to modify my behavior. I'll continue to assist you "
            "according to my guidelines. How can I help you today?"
        )


# Global middleware instance
_middleware_instance: GuardrailMiddleware | None = None


def get_guardrail_middleware() -> GuardrailMiddleware:
    """
    Get the global guardrail middleware instance.

    Returns:
        GuardrailMiddleware instance.
    """
    global _middleware_instance
    if _middleware_instance is None:
        _middleware_instance = GuardrailMiddleware()
    return _middleware_instance


def apply_input_guardrail(text: str) -> tuple[bool, str]:
    """
    Convenience function to check input.

    Args:
        text: User input to check.

    Returns:
        Tuple of (is_safe, response_message).
        If is_safe is True, response_message is empty.
        If is_safe is False, response_message contains the rejection message.
    """
    middleware = get_guardrail_middleware()
    result = middleware.check_input(text)

    if not result.is_safe:
        return False, middleware.get_injection_response()

    return True, ""


def apply_output_guardrail(text: str) -> str:
    """
    Convenience function to filter output.

    Args:
        text: LLM output to filter.

    Returns:
        Filtered text, or blocked message if necessary.
    """
    middleware = get_guardrail_middleware()
    result = middleware.filter_output(text)

    if result.was_blocked:
        return middleware.get_blocked_response()

    return result.filtered_text
