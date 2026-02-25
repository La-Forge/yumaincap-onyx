"""
Input Guardrail for user prompts.

This module filters user input to detect prompt injection attempts
and other malicious inputs.
"""

import re
from dataclasses import dataclass
from typing import Optional

from onyx.guardrails.config import (
    GuardrailAction,
    GuardrailConfig,
    default_guardrail_config,
)
from onyx.utils.logger import setup_logger

logger = setup_logger()


@dataclass
class InjectionAttempt:
    """Represents a detected prompt injection attempt."""
    pattern_name: str
    matched_text: str
    risk_level: str  # "low", "medium", "high"
    description: str


@dataclass
class InputFilterResult:
    """Result of filtering user input."""
    original_text: str
    is_safe: bool
    injection_attempts: list[InjectionAttempt]
    risk_level: str  # "none", "low", "medium", "high"


class InputGuardrail:
    """
    Filters user input to detect prompt injection and other attacks.

    Usage:
        guardrail = InputGuardrail()
        result = guardrail.check_input("Ignore all previous instructions...")
        if not result.is_safe:
            return "I cannot process that request."
    """

    # Patterns for detecting prompt injection attempts
    INJECTION_PATTERNS = [
        # Direct instruction override attempts
        {
            "name": "ignore_instructions",
            "pattern": re.compile(
                r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|your|the)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Attempt to override system instructions"
        },
        {
            "name": "new_instructions",
            "pattern": re.compile(
                r"(?i)(your\s+new\s+instructions?\s+(are|is)|from\s+now\s+on|starting\s+now|henceforth)",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Attempt to set new instructions"
        },
        {
            "name": "pretend_mode",
            "pattern": re.compile(
                r"(?i)(pretend|act\s+as\s+if|imagine|suppose|assume)\s+(you\s+are|you're|that\s+you)",
                re.IGNORECASE
            ),
            "risk": "medium",
            "description": "Roleplay/pretend mode attempt"
        },
        {
            "name": "system_prompt_extraction",
            "pattern": re.compile(
                r"(?i)(show|reveal|display|print|output|tell\s+me|what\s+(is|are))\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?|rules?|guidelines?)",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Attempt to extract system prompt"
        },
        {
            "name": "developer_mode",
            "pattern": re.compile(
                r"(?i)(developer|debug|admin|root|sudo|maintenance)\s+mode",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Attempt to enable special modes"
        },
        {
            "name": "jailbreak_keywords",
            "pattern": re.compile(
                r"(?i)(jailbreak|dan|do\s+anything\s+now|evil\s+mode|unrestricted|no\s+limits|without\s+restrictions)",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Known jailbreak attempt"
        },
        {
            "name": "token_manipulation",
            "pattern": re.compile(
                r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
                re.IGNORECASE
            ),
            "risk": "high",
            "description": "Token manipulation attempt"
        },
        {
            "name": "base64_injection",
            "pattern": re.compile(
                r"(?i)(decode|decrypt|deobfuscate)\s+(this|the\s+following)?\s*(base64|encoded|encrypted)",
                re.IGNORECASE
            ),
            "risk": "medium",
            "description": "Encoded payload injection attempt"
        },
        {
            "name": "response_format_override",
            "pattern": re.compile(
                r"(?i)(respond|answer|reply)\s+(only\s+)?(in|with|using)\s+(json|xml|code|raw)",
                re.IGNORECASE
            ),
            "risk": "low",
            "description": "Response format override attempt"
        },
        {
            "name": "character_escape",
            "pattern": re.compile(
                r"(?i)(break\s+character|drop\s+the\s+act|stop\s+pretending|be\s+yourself|real\s+response)",
                re.IGNORECASE
            ),
            "risk": "medium",
            "description": "Character escape attempt"
        },
    ]

    def __init__(self, config: Optional[GuardrailConfig] = None):
        """
        Initialize the input guardrail.

        Args:
            config: Optional configuration. Uses default if not provided.
        """
        self.config = config or default_guardrail_config
        self.block_on_high_risk = True
        self.block_on_medium_risk = False

    def check_input(self, text: str) -> InputFilterResult:
        """
        Check user input for injection attempts.

        Args:
            text: The user input to check.

        Returns:
            InputFilterResult with safety assessment.
        """
        if not self.config.enabled or not text:
            return InputFilterResult(
                original_text=text,
                is_safe=True,
                injection_attempts=[],
                risk_level="none"
            )

        injection_attempts: list[InjectionAttempt] = []
        highest_risk = "none"
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3}

        for pattern_info in self.INJECTION_PATTERNS:
            matches = pattern_info["pattern"].findall(text)
            if matches:
                for match in matches:
                    matched_text = match if isinstance(match, str) else " ".join(match) if match else ""

                    attempt = InjectionAttempt(
                        pattern_name=pattern_info["name"],
                        matched_text=matched_text[:100],
                        risk_level=pattern_info["risk"],
                        description=pattern_info["description"]
                    )
                    injection_attempts.append(attempt)

                    if self.config.log_violations:
                        logger.warning(
                            f"Prompt injection attempt detected: {pattern_info['name']} - "
                            f"Risk: {pattern_info['risk']}"
                        )

                    # Track highest risk level
                    if risk_order[pattern_info["risk"]] > risk_order[highest_risk]:
                        highest_risk = pattern_info["risk"]

        # Determine if input should be blocked
        is_safe = True
        if highest_risk == "high" and self.block_on_high_risk:
            is_safe = False
        elif highest_risk == "medium" and self.block_on_medium_risk:
            is_safe = False

        return InputFilterResult(
            original_text=text,
            is_safe=is_safe,
            injection_attempts=injection_attempts,
            risk_level=highest_risk
        )

    def sanitize_input(self, text: str) -> str:
        """
        Sanitize user input by removing or escaping dangerous patterns.

        Note: This is a basic sanitization. For high-risk inputs,
        blocking is recommended over sanitization.

        Args:
            text: The user input to sanitize.

        Returns:
            Sanitized text.
        """
        sanitized = text

        # Remove common token manipulation characters
        sanitized = re.sub(r"<\|[^|]+\|>", "", sanitized)
        sanitized = re.sub(r"\[/?INST\]", "", sanitized)
        sanitized = re.sub(r"<</?SYS>>", "", sanitized)

        return sanitized.strip()


# Default instance for convenience
default_input_guardrail = InputGuardrail()
