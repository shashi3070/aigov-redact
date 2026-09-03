from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone


class TokenGenerator:
    """Generates opaque, deterministic-within-scope tokens.

    Token format: <TYPE_PREFIX>_<hex8>
    Examples: <EMAIL_a7f2b1c3>, <SSN_9e1d4f08>, <CUSTOMER_2c8a7b5e>

    Deterministic mode (default):
        Same (type, value, date_scope) -> same token
        Different date -> different token

    Random mode:
        Always generates a new unique token
    """

    def __init__(self, session_key: bytes | None = None):
        self._key = session_key or secrets.token_bytes(32)

    def generate(
        self,
        entity_type: str,
        value: str,
        deterministic: bool = True,
        date_scope: str | None = None,
    ) -> str:
        """Generate a token for an entity value.

        Args:
            entity_type: e.g., "EMAIL", "SSN", "CUSTOMER"
            value: The original sensitive value
            deterministic: If True, same inputs produce same token
            date_scope: UTC date string (e.g., "2026-09-03").
                If None, uses current UTC date.
        """
        if not deterministic:
            return self._random_token(entity_type)

        if date_scope is None:
            date_scope = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        composite = f"{date_scope}|{entity_type}|{value}"
        mac = hmac.new(self._key, composite.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"<{entity_type}_{mac}>"

    def _random_token(self, entity_type: str) -> str:
        suffix = secrets.token_hex(4)
        return f"<{entity_type}_{suffix}>"
