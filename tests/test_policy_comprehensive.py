from __future__ import annotations

from aigov_redact.policy.engine import (
    Action,
    DateRule,
    EntityRule,
    NumberRule,
    Policy,
)


class TestPolicyDefaults:
    def test_default_name(self):
        assert Policy().name == "default"

    def test_default_get_entity_action_is_redact(self):
        assert Policy().get_entity_action("ANY_TYPE") == Action.REDACT

    def test_default_actions_are_strings(self):
        assert Policy().get_entity_action("EMAIL") == Action.REDACT
        assert Action.REDACT == "redact"

    def test_default_not_reversible(self):
        assert Policy().reversible is False

    def test_default_failure_mode(self):
        assert Policy().failure_mode == "fail_open"

    def test_default_privacy_level(self):
        assert Policy().privacy_level == "strict"

    def test_default_has_no_number_rules(self):
        assert Policy().number_rules == {}

    def test_default_has_no_date_rule(self):
        assert Policy().date_rule is None


class TestPolicyCustomRules:
    def test_entity_rule_actions(self):
        p = Policy(
            entity_rules={
                "EMAIL": EntityRule(entity_type="EMAIL", action=Action.TOKENIZE),
                "SSN": EntityRule(entity_type="SSN", action=Action.HASH),
                "PHONE": EntityRule(entity_type="PHONE", action=Action.BLOCK),
            }
        )
        assert p.get_entity_action("EMAIL") == Action.TOKENIZE
        assert p.get_entity_action("SSN") == Action.HASH
        assert p.get_entity_action("PHONE") == Action.BLOCK

    def test_number_rules_fields(self):
        p = Policy(
            number_rules={
                "currency": NumberRule(
                    numeric_type="currency",
                    action=Action.SCALE,
                    mode="scale",
                    factor=1.25,
                    min_factor=0.5,
                    max_factor=2.0,
                    additive_offset=10.0,
                )
            }
        )
        rule = p.get_number_rule("currency")
        assert rule.factor == 1.25
        assert rule.min_factor == 0.5
        assert rule.max_factor == 2.0
        assert rule.additive_offset == 10.0

    def test_missing_number_rule_returns_none(self):
        p = Policy()
        assert p.get_number_rule("currency") is None

    def test_date_rule_fields(self):
        p = Policy(date_rule=DateRule(action=Action.SCALE, mode="shift", shift_days=90))
        assert p.date_rule is not None
        assert p.date_rule.action == Action.SCALE
        assert p.date_rule.mode == "shift"
        assert p.date_rule.shift_days == 90


class TestPolicyPrebuilt:
    def test_strict_blocks_secrets(self):
        p = Policy.strict()
        for secret_type in ("API_KEY", "PASSWORD", "PRIVATE_KEY", "JWT_TOKEN", "AZURE_OPENAI_KEY"):
            assert p.get_entity_action(secret_type) == Action.BLOCK

    def test_strict_redacts_pii(self):
        p = Policy.strict()
        for pii in ("EMAIL", "SSN", "CREDIT_CARD", "PHONE_US", "PHONE_INTL"):
            assert p.get_entity_action(pii) == Action.REDACT

    def test_enterprise_blocks_secrets(self):
        p = Policy.enterprise()
        assert p.get_entity_action("API_KEY") == Action.BLOCK
        assert p.get_entity_action("PASSWORD") == Action.BLOCK
        assert p.get_entity_action("PRIVATE_KEY") == Action.BLOCK

    def test_enterprise_balanced_privacy(self):
        assert Policy.enterprise().privacy_level == "balanced"

    def test_permissive_only_blocks_secrets(self):
        p = Policy.permissive()
        # Secrets blocked
        assert p.get_entity_action("API_KEY") == Action.BLOCK
        # Other types fall back to default REDACT
        assert p.get_entity_action("EMAIL") == Action.REDACT
        assert p.get_entity_action("PHONE") == Action.REDACT

    def test_permissive_not_reversible(self):
        assert Policy.permissive().reversible is False

    def test_prebuilt_have_no_number_rules(self):
        for p in (Policy.strict(), Policy.enterprise(), Policy.permissive()):
            assert p.number_rules == {}, f"{p.name} should have no number rules"

    def test_prebuilt_have_no_date_rule(self):
        for p in (Policy.strict(), Policy.enterprise(), Policy.permissive()):
            assert p.date_rule is None


class TestEntityRuleModel:
    def test_default_abstract_fields_none(self):
        r = EntityRule(entity_type="EMAIL", action=Action.REDACT)
        assert r.abstract_fields is None
        assert r.replacement_token is None

    def test_with_abstract_fields(self):
        r = EntityRule(
            entity_type="CUSTOMER",
            action=Action.ABSTRACT,
            abstract_fields={"industry": "Conglomerate"},
            replacement_token="<CUST>",
        )
        assert r.abstract_fields == {"industry": "Conglomerate"}
        assert r.replacement_token == "<CUST>"

    def test_action_enum_all_members(self):
        actions = {a.value for a in Action}
        assert actions == {
            "allow", "redact", "tokenize", "mask", "hash",
            "remove", "block", "preserve", "abstract", "scale", "audit",
        }
