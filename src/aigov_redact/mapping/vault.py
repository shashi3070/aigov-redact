from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any


class MappingVault:
    """Thread-safe, date-scoped in-memory store for entity-to-token mappings.

    Design:
    - Key = (utc_date, entity_type, original_value)
    - Value = (token, metadata)
    - Same entity on same UTC date = same token (deterministic)
    - Same entity on different UTC date = different token (fresh mapping)
    - Mappings never persist to disk or logs
    - Thread-safe via reentrant lock

    Usage:
        vault = MappingVault()
        token = vault.register("EMAIL", "john@example.com")
        # -> "<EMAIL_a7f2b1c3>"

        original = vault.resolve("<EMAIL_a7f2b1c3>")
        # -> "john@example.com"

        # Same entity, same date = same token
        token2 = vault.register("EMAIL", "john@example.com")
        assert token == token2  # True -- deterministic
    """

    def __init__(
        self,
        scope: str = "date",
        ttl: int | None = None,
        session_key: bytes | None = None,
    ):
        """
        Args:
            scope: "date" (default) or "session"
                - "date": same entity on same UTC date = same token
                - "session": each MappingVault instance gets unique tokens
            ttl: Optional time-to-live in seconds for mappings
            session_key: Optional HMAC key for token generation.
                If None, generates a random key per vault instance.
        """
        self._scope = scope
        self._ttl = ttl
        self._session_key = session_key or secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._forward: dict[str, dict[str, Any]] = {}
        self._reverse: dict[str, str] = {}
        self._created_at: dict[str, float] = {}

    def _get_date_key(self) -> str:
        if self._scope == "session":
            return secrets.token_hex(8)
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _make_composite_key(self, entity_type: str, value: str) -> str:
        date_key = self._get_date_key()
        return f"{date_key}|{entity_type}|{value}"

    def _generate_token(self, entity_type: str, value: str) -> str:
        composite = self._make_composite_key(entity_type, value)
        mac = hmac.new(self._session_key, composite.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"<{entity_type}_{mac}>"

    def register(
        self,
        entity_type: str,
        original_value: str,
        metadata: dict[str, Any] | None = None,
        explicit_token: str | None = None,
    ) -> str:
        """Register an entity and return its token.

        If already registered (same date/type/value), returns existing token.
        When ``explicit_token`` is provided, that token is used instead of a
        generated one (e.g. for user-supplied manual replacement tokens), so
        the mapping records token -> original value.
        """
        composite_key = self._make_composite_key(entity_type, original_value)

        with self._lock:
            if composite_key in self._reverse:
                return self._reverse[composite_key]

            token = explicit_token or self._generate_token(entity_type, original_value)

            self._forward[token] = {
                "type": entity_type,
                "original": original_value,
                "metadata": metadata or {},
                "created_at": time.time(),
            }
            self._reverse[composite_key] = token
            self._created_at[token] = time.time()

            return token

    def resolve(self, token: str) -> str | None:
        """Resolve a token back to its original value."""
        with self._lock:
            entry = self._forward.get(token)
            if entry is None:
                return None
            if self._is_expired(token):
                self._remove(token)
                return None
            return entry["original"]

    def resolve_text(self, text: str) -> str:
        """Replace all tokens in text with their original values."""
        with self._lock:
            sorted_tokens = sorted(self._forward.keys(), key=len, reverse=True)
            result = text
            for token in sorted_tokens:
                if token in result:
                    original = self._forward[token]["original"]
                    result = result.replace(token, original)
            return result

    def register_number_op(
        self,
        original: float,
        transformed: float,
        operation: str,
        factor: float | None = None,
    ) -> None:
        """Register a numeric transformation for later reversal."""
        with self._lock:
            key = f"num|{operation}|{original}"
            self._forward[key] = {
                "type": "NUMBER",
                "original": original,
                "transformed": transformed,
                "operation": operation,
                "factor": factor,
                "created_at": time.time(),
            }

    def reverse_number(self, value: float) -> float | None:
        """Reverse a numeric transformation."""
        with self._lock:
            for token, entry in self._forward.items():
                if entry.get("type") == "NUMBER" and entry.get("transformed") == value:
                    return entry["original"]
            return None

    def register_date_op(
        self,
        original: datetime,
        transformed: datetime,
    ) -> None:
        """Register a date transformation for later reversal."""
        with self._lock:
            key = f"date|{original.isoformat()}"
            self._forward[key] = {
                "type": "DATE",
                "original": original.isoformat(),
                "transformed": transformed.isoformat(),
                "created_at": time.time(),
            }

    def reverse_date(self, value: datetime) -> datetime | None:
        """Reverse a date transformation."""
        with self._lock:
            for entry in self._forward.values():
                if entry.get("type") == "DATE" and entry.get("transformed") == value.isoformat():
                    return datetime.fromisoformat(entry["original"])
            return None

    def export_mapping(self) -> dict[str, str]:
        """Export token -> original value mapping (for external use)."""
        with self._lock:
            return {
                token: entry["original"]
                for token, entry in self._forward.items()
                if entry.get("type") not in ("NUMBER", "DATE")
            }

    def _is_expired(self, token: str) -> bool:
        if self._ttl is None:
            return False
        created = self._created_at.get(token, 0)
        return (time.time() - created) > self._ttl

    def _remove(self, token: str) -> None:
        entry = self._forward.pop(token, None)
        self._created_at.pop(token, None)
        if entry:
            keys_to_remove = [k for k, v in self._reverse.items() if v == token]
            for k in keys_to_remove:
                del self._reverse[k]

    def clear(self) -> None:
        """Clear all mappings."""
        with self._lock:
            self._forward.clear()
            self._reverse.clear()
            self._created_at.clear()

    def __len__(self) -> int:
        return len(self._forward)

    def __bool__(self) -> bool:
        return True

    def __contains__(self, token: str) -> bool:
        return token in self._forward
