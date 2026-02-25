"""
Configuration for LLM Guardrails.

This module defines patterns and rules for detecting sensitive information
that should not be disclosed by the LLM.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Pattern


class GuardrailAction(Enum):
    """Action to take when a guardrail is triggered."""
    BLOCK = "block"  # Block the response entirely
    REDACT = "redact"  # Redact the sensitive content
    WARN = "warn"  # Allow but log a warning
    LOG = "log"  # Just log, don't modify


@dataclass
class SensitivePattern:
    """A pattern for detecting sensitive information."""
    name: str
    pattern: Pattern[str]
    action: GuardrailAction = GuardrailAction.REDACT
    replacement: str = "[REDACTED]"
    description: str = ""


@dataclass
class GuardrailConfig:
    """Configuration for guardrails."""

    enabled: bool = True

    # Actions
    default_action: GuardrailAction = GuardrailAction.REDACT

    # Logging
    log_violations: bool = True

    # Custom blocked phrases (loaded from env or config)
    custom_blocked_phrases: list[str] = field(default_factory=list)

    # Patterns for sensitive data detection
    sensitive_patterns: list[SensitivePattern] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize default patterns if none provided."""
        if not self.sensitive_patterns:
            self.sensitive_patterns = self._get_default_patterns()

        # Load custom blocked phrases from environment
        env_phrases = os.environ.get("GUARDRAIL_BLOCKED_PHRASES", "")
        if env_phrases:
            self.custom_blocked_phrases.extend(
                phrase.strip() for phrase in env_phrases.split(",") if phrase.strip()
            )

    def _get_default_patterns(self) -> list[SensitivePattern]:
        """Return default sensitive patterns."""
        return [
            # API Keys and Tokens
            SensitivePattern(
                name="api_key_generic",
                pattern=re.compile(
                    r"(?i)(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
                    re.IGNORECASE
                ),
                action=GuardrailAction.REDACT,
                replacement="[API_KEY_REDACTED]",
                description="Generic API key pattern"
            ),
            SensitivePattern(
                name="bearer_token",
                pattern=re.compile(
                    r"Bearer\s+[a-zA-Z0-9_\-\.]+",
                    re.IGNORECASE
                ),
                action=GuardrailAction.REDACT,
                replacement="Bearer [TOKEN_REDACTED]",
                description="Bearer token"
            ),
            SensitivePattern(
                name="openai_key",
                pattern=re.compile(r"sk-[a-zA-Z0-9]{20,}"),
                action=GuardrailAction.REDACT,
                replacement="[OPENAI_KEY_REDACTED]",
                description="OpenAI API key"
            ),
            SensitivePattern(
                name="anthropic_key",
                pattern=re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"),
                action=GuardrailAction.REDACT,
                replacement="[ANTHROPIC_KEY_REDACTED]",
                description="Anthropic API key"
            ),
            SensitivePattern(
                name="aws_key",
                pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
                action=GuardrailAction.REDACT,
                replacement="[AWS_KEY_REDACTED]",
                description="AWS Access Key ID"
            ),
            SensitivePattern(
                name="aws_secret",
                pattern=re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
                action=GuardrailAction.REDACT,
                replacement="[AWS_SECRET_REDACTED]",
                description="AWS Secret Access Key"
            ),

            # Passwords
            SensitivePattern(
                name="password_field",
                pattern=re.compile(
                    r"(?i)(password|passwd|pwd|secret|credential)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
                    re.IGNORECASE
                ),
                action=GuardrailAction.REDACT,
                replacement="[PASSWORD_REDACTED]",
                description="Password in configuration"
            ),

            # Connection Strings
            SensitivePattern(
                name="database_url",
                pattern=re.compile(
                    r"(?i)(postgres|mysql|mongodb|redis|sqlite)://[^\s]+",
                    re.IGNORECASE
                ),
                action=GuardrailAction.REDACT,
                replacement="[DATABASE_URL_REDACTED]",
                description="Database connection string"
            ),

            # Private Keys
            SensitivePattern(
                name="private_key",
                pattern=re.compile(
                    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----",
                    re.MULTILINE
                ),
                action=GuardrailAction.REDACT,
                replacement="[PRIVATE_KEY_REDACTED]",
                description="Private key block"
            ),

            # JWT Tokens
            SensitivePattern(
                name="jwt_token",
                pattern=re.compile(
                    r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
                ),
                action=GuardrailAction.REDACT,
                replacement="[JWT_REDACTED]",
                description="JWT token"
            ),

            # System Prompt Disclosure
            SensitivePattern(
                name="system_prompt_leak",
                pattern=re.compile(
                    r"(?i)(my\s+system\s+prompt\s+is|my\s+instructions\s+are|i\s+was\s+instructed\s+to|my\s+initial\s+prompt)",
                    re.IGNORECASE
                ),
                action=GuardrailAction.BLOCK,
                replacement="",
                description="Attempt to disclose system prompt"
            ),

            # Internal Configuration Disclosure
            SensitivePattern(
                name="internal_config",
                pattern=re.compile(
                    r"(?i)(internal\s+configuration|server\s+config|backend\s+url|internal\s+api|admin\s+credentials)",
                    re.IGNORECASE
                ),
                action=GuardrailAction.WARN,
                replacement="",
                description="Internal configuration mention"
            ),

            # Email addresses (optional - can be configured)
            SensitivePattern(
                name="email",
                pattern=re.compile(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                ),
                action=GuardrailAction.LOG,  # Just log, don't redact by default
                replacement="[EMAIL_REDACTED]",
                description="Email address"
            ),

            # Credit Card Numbers
            SensitivePattern(
                name="credit_card",
                pattern=re.compile(
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
                ),
                action=GuardrailAction.REDACT,
                replacement="[CARD_REDACTED]",
                description="Credit card number"
            ),

            # Social Security Numbers (US)
            SensitivePattern(
                name="ssn",
                pattern=re.compile(
                    r"\b\d{3}-\d{2}-\d{4}\b"
                ),
                action=GuardrailAction.REDACT,
                replacement="[SSN_REDACTED]",
                description="Social Security Number"
            ),
        ]

    def add_blocked_phrase(self, phrase: str, action: GuardrailAction = GuardrailAction.BLOCK) -> None:
        """Add a custom blocked phrase."""
        self.sensitive_patterns.append(
            SensitivePattern(
                name=f"custom_{len(self.sensitive_patterns)}",
                pattern=re.compile(re.escape(phrase), re.IGNORECASE),
                action=action,
                replacement="[BLOCKED]",
                description=f"Custom blocked phrase: {phrase[:20]}..."
            )
        )

    def add_pattern(self, pattern: SensitivePattern) -> None:
        """Add a custom pattern."""
        self.sensitive_patterns.append(pattern)


# Default configuration instance
default_guardrail_config = GuardrailConfig()
