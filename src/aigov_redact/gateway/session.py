from __future__ import annotations

import hashlib
from typing import Any

from aigov_redact.mapping.vault import MappingVault
from aigov_redact.policy.engine import Action
from aigov_redact.transformation.dates import DateTransformer
from aigov_redact.transformation.numbers import NumberTransformer


class GatewaySession:
    """A single protect -> resolve lifecycle.

    Created by PrivacyGateway.protect(), this object holds:
    - .text: the protected text safe for LLM consumption
    - .original: the original unprotected text
    - .mapping: token -> original value mapping
    - .resolve(llm_output): restore original values in LLM response
    """

    def __init__(self, gateway: Any, original_text: str, task: str | None = None):
        self._gateway = gateway
        self._original_text = original_text
        self._task = task
        self._policy = gateway._policy
        self._vault = MappingVault()
        self._number_transformer = NumberTransformer(self._vault)
        self._date_transformer = DateTransformer(self._vault)
        self._protected_text = self._apply_protection(original_text)

    def _apply_protection(self, text: str) -> str:
        result = text

        if self._gateway._replacements:
            for original_value, replacement in self._gateway._replacements.items():
                if isinstance(replacement, dict):
                    token = replacement.get("token", f"<ENTITY_{original_value[:8]}>")
                else:
                    token = replacement
                if original_value in result:
                    self._vault.register(
                        "ENTITY", original_value, {"token": token}, explicit_token=token
                    )
                    result = result.replace(original_value, token)

        detection = self._gateway._detector.detect(result)

        for entity in sorted(detection, key=lambda e: e.start, reverse=True):
            action = self._policy.get_entity_action(entity.type)

            if action in (Action.REDACT, Action.TOKENIZE):
                token = self._vault.register(entity.type, entity.text)
                result = result[: entity.start] + token + result[entity.end :]
            elif action == Action.MASK:
                mask = "*" * (entity.end - entity.start)
                result = result[: entity.start] + mask + result[entity.end :]
            elif action == Action.HASH:
                h = hashlib.sha256(entity.text.encode()).hexdigest()[:8]
                token = f"<{entity.type}_{h}>"
                self._vault.register(entity.type, entity.text)
                result = result[: entity.start] + token + result[entity.end :]
            elif action == Action.REMOVE:
                result = result[: entity.start] + result[entity.end :]
            elif action == Action.BLOCK:
                raise ValueError(f"BLOCKED: {entity.type} detected: {entity.text[:20]}...")

        for num_type, num_rule in self._policy.number_rules.items():
            if num_rule.mode == "scale" and num_rule.factor:
                result = self._number_transformer.scale(result, num_rule.factor)
            elif num_rule.mode == "random_scale":
                result = self._number_transformer.random_scale(
                    result,
                    num_rule.min_factor or 0.8,
                    num_rule.max_factor or 1.4,
                )
            elif num_rule.mode == "range":
                result = self._number_transformer.range_transform(result)

        if self._policy.date_rule and self._policy.date_rule.mode == "shift":
            days = self._policy.date_rule.shift_days or 173
            result = self._date_transformer.shift(result, days)

        return result

    @property
    def text(self) -> str:
        """The protected/safe text for LLM consumption."""
        return self._protected_text

    @property
    def original(self) -> str:
        """The original unprotected text."""
        return self._original_text

    @property
    def mapping(self) -> dict[str, str]:
        """Token -> original value mapping."""
        return self._vault.export_mapping()

    def resolve(self, text: str) -> str:
        """Restore original values in LLM output."""
        result = text
        result = self._number_transformer.reverse(result)
        result = self._date_transformer.reverse(result)

        mapping = self._vault.export_mapping()
        for token in sorted(mapping.keys(), key=len, reverse=True):
            if token in result:
                result = result.replace(token, mapping[token])

        return result

    def resolve_json(self, data: dict) -> dict:
        """Restore original values in a JSON response."""
        import json

        text = json.dumps(data)
        resolved = self.resolve(text)
        return json.loads(resolved)
