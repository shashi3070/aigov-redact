from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    TOKENIZE = "tokenize"
    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"
    BLOCK = "block"
    PRESERVE = "preserve"
    ABSTRACT = "abstract"
    SCALE = "scale"
    AUDIT = "audit"


class EntityRule(BaseModel):
    entity_type: str
    action: Action
    abstract_fields: dict[str, str] | None = None
    replacement_token: str | None = None


class NumberRule(BaseModel):
    numeric_type: str
    action: Action
    mode: str = "preserve"
    factor: float | None = None
    min_factor: float | None = None
    max_factor: float | None = None
    additive_offset: float | None = None


class DateRule(BaseModel):
    action: Action
    mode: str = "preserve"
    shift_days: int | None = None


class Policy(BaseModel):
    """Policy engine for controlling how each entity type is handled."""

    name: str = "default"
    entity_rules: dict[str, EntityRule] = {}
    number_rules: dict[str, NumberRule] = {}
    date_rule: DateRule | None = None
    failure_mode: str = "fail_open"
    reversible: bool = False
    privacy_level: str = "strict"
    replacements: dict[str, Any] | None = None

    def get_entity_action(self, entity_type: str) -> Action:
        rule = self.entity_rules.get(entity_type)
        if rule:
            return rule.action
        return Action.REDACT

    def get_number_rule(self, numeric_type: str) -> NumberRule | None:
        return self.number_rules.get(numeric_type)

    @classmethod
    def strict(cls) -> Policy:
        """Pre-built strict policy: tokenize everything, block secrets."""
        return cls(
            name="strict",
            reversible=True,
            entity_rules={
                "EMAIL": EntityRule(entity_type="EMAIL", action=Action.REDACT),
                "SSN": EntityRule(entity_type="SSN", action=Action.REDACT),
                "CREDIT_CARD": EntityRule(entity_type="CREDIT_CARD", action=Action.REDACT),
                "PHONE_US": EntityRule(entity_type="PHONE_US", action=Action.REDACT),
                "PHONE_INTL": EntityRule(entity_type="PHONE_INTL", action=Action.REDACT),
                "API_KEY": EntityRule(entity_type="API_KEY", action=Action.BLOCK),
                "PASSWORD": EntityRule(entity_type="PASSWORD", action=Action.BLOCK),
                "PRIVATE_KEY": EntityRule(entity_type="PRIVATE_KEY", action=Action.BLOCK),
                "JWT_TOKEN": EntityRule(entity_type="JWT_TOKEN", action=Action.BLOCK),
                "AZURE_OPENAI_KEY": EntityRule(entity_type="AZURE_OPENAI_KEY", action=Action.BLOCK),
            },
        )

    @classmethod
    def enterprise(cls) -> Policy:
        """Pre-built enterprise policy with semantic abstraction."""
        return cls(
            name="enterprise",
            reversible=True,
            privacy_level="balanced",
            entity_rules={
                "EMAIL": EntityRule(entity_type="EMAIL", action=Action.REDACT),
                "SSN": EntityRule(entity_type="SSN", action=Action.REDACT),
                "CREDIT_CARD": EntityRule(entity_type="CREDIT_CARD", action=Action.REDACT),
                "API_KEY": EntityRule(entity_type="API_KEY", action=Action.BLOCK),
                "PASSWORD": EntityRule(entity_type="PASSWORD", action=Action.BLOCK),
                "PRIVATE_KEY": EntityRule(entity_type="PRIVATE_KEY", action=Action.BLOCK),
            },
        )

    @classmethod
    def permissive(cls) -> Policy:
        """Pre-built permissive policy: only block secrets, preserve rest."""
        return cls(
            name="permissive",
            reversible=False,
            entity_rules={
                "API_KEY": EntityRule(entity_type="API_KEY", action=Action.BLOCK),
                "PASSWORD": EntityRule(entity_type="PASSWORD", action=Action.BLOCK),
                "PRIVATE_KEY": EntityRule(entity_type="PRIVATE_KEY", action=Action.BLOCK),
                "JWT_TOKEN": EntityRule(entity_type="JWT_TOKEN", action=Action.BLOCK),
            },
        )
