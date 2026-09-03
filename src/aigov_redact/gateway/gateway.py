from __future__ import annotations

from typing import Any

from aigov_redact.detector import Detector, create_detector
from aigov_redact.gateway.session import GatewaySession
from aigov_redact.patterns import PIIDefinition
from aigov_redact.policy.engine import Policy
from aigov_redact.transformation.semantic import SemanticAbstracter


class PrivacyGateway:
    """Main entry point for the enhanced library.

    Provides: protect() -> LLM -> resolve() workflow.

    Usage:
        gateway = PrivacyGateway(policy="enterprise")
        session = gateway.protect("Reliance Industries sold Product-X to Tata")
        safe_text = session.text  # safe for LLM
        original = session.resolve(llm_response)  # restore original values
    """

    def __init__(
        self,
        policy: Policy | str = "default",
        reversible: bool | None = None,
        replacements: dict[str, Any] | str | None = None,
        patterns: str | list[dict] | None = None,
        enabled_types: list[str] | None = None,
        disabled_types: list[str] | None = None,
        custom_patterns: list[PIIDefinition] | None = None,
        excluded_patterns: list[str] | None = None,
    ):
        if isinstance(policy, str):
            policy_map = {
                "default": Policy(),
                "strict": Policy.strict(),
                "enterprise": Policy.enterprise(),
                "permissive": Policy.permissive(),
            }
            self._policy = policy_map.get(policy, Policy())
        else:
            self._policy = policy

        if reversible is not None:
            self._policy.reversible = reversible

        self._replacements = self._load_replacements(replacements)
        self._custom_patterns = self._load_patterns(patterns)

        self._detector = create_detector(
            enabled_types=enabled_types,
            disabled_types=disabled_types,
            custom_patterns=custom_patterns or self._custom_patterns,
            excluded_patterns=excluded_patterns,
        )

        self._semantic_abstracter = SemanticAbstracter(self._replacements)

    def _load_replacements(self, replacements: Any) -> dict[str, Any]:
        if replacements is None:
            return {}
        if isinstance(replacements, str):
            import yaml
            with open(replacements, "r") as f:
                data = yaml.safe_load(f)
            return data.get("replacements", data)
        if isinstance(replacements, list):
            return {item.get("key", ""): item.get("value", "") for item in replacements}
        return replacements

    def _load_patterns(self, patterns: Any) -> list[PIIDefinition]:
        if patterns is None:
            return []
        if isinstance(patterns, str):
            import yaml
            with open(patterns, "r") as f:
                data = yaml.safe_load(f)
            return [PIIDefinition(**p) for p in data.get("patterns", [])]
        if isinstance(patterns, list):
            return [PIIDefinition(**p) for p in patterns]
        return []

    def protect(
        self,
        text: str,
        task: str | None = None,
    ) -> GatewaySession:
        """Protect input data for LLM consumption.

        Returns a GatewaySession with:
        - .text: safe text for LLM
        - .mapping: token -> original value
        - .resolve(response): restore original values
        """
        session = GatewaySession(self, text, task)
        return session

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def detector(self) -> Detector:
        return self._detector
