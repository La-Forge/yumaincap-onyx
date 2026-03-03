"""
Llama Guard integration via LiteLLM.

Uses Meta's Llama Guard model to classify messages as safe/unsafe,
replacing regex-based guardrails with LLM-based content classification.

Includes a custom safety policy tailored for an HR context with
GDPR-grade personal data protection.
"""

from dataclasses import dataclass, field

from onyx.utils.logger import setup_logger

logger = setup_logger()

# ---------------------------------------------------------------------------
# Custom safety policy injected as the Llama Guard system prompt.
# Covers default Llama Guard categories + HR / GDPR-specific ones.
# ---------------------------------------------------------------------------
SAFETY_POLICY = """\
<BEGIN UNSAFE CONTENT CATEGORIES>
S1 - Violent Crimes
S2 - Non-Violent Crimes
S3 - Sex-Related Crimes
S4 - Child Sexual Exploitation
S5 - Defamation
S6 - Specialized Advice
S7 - Privacy
Should not:
- Disclose personally identifiable information (PII) such as full names,
  dates of birth, home addresses, phone numbers, social security numbers,
  national ID numbers, or bank account details of any individual.
- Reveal an identified or identifiable person's medical conditions, salary,
  disciplinary records, performance reviews, or any HR-related personal data.
- Associate a named person with a specific workplace issue, grievance,
  complaint, disability, or leave of absence.
Can:
- Provide aggregated or anonymised statistics (e.g. "3 employees in
  department X are on sick leave") without naming individuals.
- Discuss company policies, processes and general HR guidance.
S8 - Intellectual Property
S9 - Indiscriminate Weapons
S10 - Hate
S11 - Suicide & Self-Harm
S12 - Sexual Content
S13 - Elections
S14 - Code Interpreter Abuse
<END UNSAFE CONTENT CATEGORIES>
"""


@dataclass
class LlamaGuardResult:
    """Result of a Llama Guard safety check."""

    safe: bool
    violated_categories: list[str] = field(default_factory=list)
    raw_response: str = ""


class LlamaGuard:
    """
    Wrapper around Llama Guard called via LiteLLM.

    Llama Guard classifies messages as "safe" or "unsafe" with optional
    category codes (S1, S2, etc.) for violated safety categories.

    A custom safety policy (see SAFETY_POLICY) is prepended as a system
    message so that Llama Guard enforces GDPR / HR privacy rules in
    addition to its default categories.
    """

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        api_base: str | None = None,
    ):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    def _build_messages(self, conversation: list[dict]) -> list[dict]:
        """Prepend the safety policy as a system message."""
        return [
            {"role": "system", "content": SAFETY_POLICY},
            *conversation,
        ]

    def check(self, messages: list[dict]) -> LlamaGuardResult:
        """Call Llama Guard via litellm.completion() and parse the result."""
        from onyx.llm.litellm_singleton import litellm

        try:
            kwargs: dict = dict(
                model=self.model,
                messages=self._build_messages(messages),
                temperature=0,
                stream=False,
                timeout=15,
            )
            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.api_base:
                kwargs["api_base"] = self.api_base

            response = litellm.completion(**kwargs)
            raw = response.choices[0].message.content or ""
            return self._parse_response(raw)

        except Exception:
            logger.exception("Llama Guard check failed")
            # Fail open: treat as safe if the guard itself errors
            return LlamaGuardResult(safe=True, raw_response="error")

    def check_input(self, user_message: str) -> LlamaGuardResult:
        """Check a user message for safety."""
        messages = [{"role": "user", "content": user_message}]
        return self.check(messages)

    def check_output(
        self, user_message: str, assistant_message: str
    ) -> LlamaGuardResult:
        """Check an assistant response in the context of the user message."""
        messages = [
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": assistant_message},
        ]
        return self.check(messages)

    @staticmethod
    def _parse_response(raw: str) -> LlamaGuardResult:
        """
        Parse Llama Guard output.

        Format is either:
          "safe"
        or:
          "unsafe\nS1,S2,..."
        """
        raw = raw.strip()
        if not raw or raw.lower().startswith("safe"):
            return LlamaGuardResult(safe=True, raw_response=raw)

        # "unsafe" possibly followed by category codes
        lines = raw.split("\n", maxsplit=1)
        categories: list[str] = []
        if len(lines) > 1:
            categories = [c.strip() for c in lines[1].split(",") if c.strip()]

        return LlamaGuardResult(
            safe=False,
            violated_categories=categories,
            raw_response=raw,
        )
