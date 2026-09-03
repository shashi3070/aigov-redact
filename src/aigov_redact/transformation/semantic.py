from __future__ import annotations

from typing import Any


class SemanticAbstracter:
    """Provides semantic abstraction for enterprise entities.

    When a user provides replacements with metadata, this class
    applies semantic attributes to protect business-sensitive information
    while preserving the semantic meaning for LLM processing.

    Usage:
        abstracter = SemanticAbstracter({
            "Reliance Industries": {
                "token": "<CUST_REL>",
                "semantic": {
                    "industry": "Conglomerate",
                    "region": "India",
                    "segment": "Enterprise",
                }
            }
        })

        text = "Reliance Industries reported strong Q3 results"
        result = abstracter.abstract(text)
        # -> "<CUST_REL> reported strong Q3 results"
    """

    def __init__(self, replacements: dict[str, Any] | None = None):
        self._replacements = replacements or {}

    def abstract(self, text: str) -> str:
        """Apply semantic abstraction to text using configured replacements."""
        result = text
        for original_value, replacement in self._replacements.items():
            if original_value in result:
                if isinstance(replacement, dict):
                    token = replacement.get("token", f"<ENTITY_{original_value[:8]}>")
                else:
                    token = replacement
                result = result.replace(original_value, token)
        return result

    def get_metadata(self, entity_type: str) -> dict[str, Any] | None:
        """Get semantic metadata for an entity type."""
        replacement = self._replacements.get(entity_type)
        if isinstance(replacement, dict):
            return replacement.get("semantic")
        return None
