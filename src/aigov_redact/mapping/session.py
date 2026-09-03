from __future__ import annotations

from aigov_redact.mapping.token_generator import TokenGenerator
from aigov_redact.mapping.vault import MappingVault


class MappingSession:
    """Scoped session binding a vault + generator.

    Provides the protect_text -> resolve_text workflow.
    """

    def __init__(
        self,
        vault: MappingVault | None = None,
        generator: TokenGenerator | None = None,
    ):
        self._vault = vault or MappingVault()
        self._generator = generator or TokenGenerator(self._vault._session_key)

    @property
    def vault(self) -> MappingVault:
        return self._vault

    @property
    def generator(self) -> TokenGenerator:
        return self._generator

    def get_token(self, entity_type: str, value: str) -> str:
        """Get or create a token for an entity value."""
        return self._vault.register(entity_type, value)

    def resolve(self, token: str) -> str | None:
        """Resolve a token to its original value."""
        return self._vault.resolve(token)

    def resolve_text(self, text: str) -> str:
        """Resolve all tokens in text."""
        return self._vault.resolve_text(text)

    def clear(self) -> None:
        """Clear all mappings."""
        self._vault.clear()

    def export(self) -> dict[str, str]:
        """Export the token -> original mapping."""
        return self._vault.export_mapping()
