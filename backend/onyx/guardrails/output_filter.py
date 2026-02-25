"""
Output Guardrail for LLM responses.

This module filters LLM output to prevent disclosure of sensitive information.
"""

from dataclasses import dataclass
from typing import Optional

from onyx.guardrails.config import (
    GuardrailAction,
    GuardrailConfig,
    SensitivePattern,
    default_guardrail_config,
)
from onyx.utils.logger import setup_logger

logger = setup_logger()


@dataclass
class GuardrailViolation:
    """Represents a guardrail violation."""
    pattern_name: str
    matched_text: str
    action: GuardrailAction
    description: str


@dataclass
class FilterResult:
    """Result of applying guardrails to text."""
    original_text: str
    filtered_text: str
    was_modified: bool
    was_blocked: bool
    violations: list[GuardrailViolation]


class OutputGuardrail:
    """
    Filters LLM output to prevent disclosure of sensitive information.

    Usage:
        guardrail = OutputGuardrail()
        result = guardrail.filter_response("Here is an API key: sk-abc123...")
        if result.was_blocked:
            return "I cannot provide that information."
        return result.filtered_text
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        """
        Initialize the output guardrail.

        Args:
            config: Optional configuration. Uses default if not provided.
        """
        self.config = config or default_guardrail_config

    def filter_response(self, text: str) -> FilterResult:
        """
        Filter an LLM response for sensitive information.

        Args:
            text: The LLM response text to filter.

        Returns:
            FilterResult with filtered text and violation details.
        """
        if not self.config.enabled or not text:
            return FilterResult(
                original_text=text,
                filtered_text=text,
                was_modified=False,
                was_blocked=False,
                violations=[]
            )

        violations: list[GuardrailViolation] = []
        filtered_text = text
        was_blocked = False

        for pattern in self.config.sensitive_patterns:
            matches = pattern.pattern.findall(filtered_text)
            if matches:
                for match in matches:
                    # Handle tuple matches from groups
                    matched_text = match if isinstance(match, str) else match[0] if match else ""

                    violation = GuardrailViolation(
                        pattern_name=pattern.name,
                        matched_text=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                        action=pattern.action,
                        description=pattern.description
                    )
                    violations.append(violation)

                    if self.config.log_violations:
                        logger.warning(
                            f"Guardrail violation detected: {pattern.name} - "
                            f"Action: {pattern.action.value}"
                        )

                # Apply action based on pattern configuration
                if pattern.action == GuardrailAction.BLOCK:
                    was_blocked = True
                    break
                elif pattern.action == GuardrailAction.REDACT:
                    filtered_text = pattern.pattern.sub(pattern.replacement, filtered_text)
                elif pattern.action == GuardrailAction.WARN:
                    logger.warning(
                        f"Guardrail warning: Pattern '{pattern.name}' matched in output"
                    )
                # LOG action: just log, don't modify

        was_modified = filtered_text != text

        return FilterResult(
            original_text=text,
            filtered_text="" if was_blocked else filtered_text,
            was_modified=was_modified,
            was_blocked=was_blocked,
            violations=violations
        )

    def check_for_violations(self, text: str) -> list[GuardrailViolation]:
        """
        Check text for violations without modifying it.

        Args:
            text: The text to check.

        Returns:
            List of violations found.
        """
        result = self.filter_response(text)
        return result.violations

    def is_safe(self, text: str) -> bool:
        """
        Check if text passes all guardrails.

        Args:
            text: The text to check.

        Returns:
            True if no blocking violations were found.
        """
        result = self.filter_response(text)
        return not result.was_blocked and not any(
            v.action == GuardrailAction.BLOCK for v in result.violations
        )


# Default instance for convenience
default_output_guardrail = OutputGuardrail()
