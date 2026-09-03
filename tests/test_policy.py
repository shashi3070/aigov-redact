from aigov_redact.policy.engine import (
    Action,
    DateRule,
    EntityRule,
    NumberRule,
    Policy,
)


class TestPolicy:
    def test_default_policy(self):
        policy = Policy()
        assert policy.name == "default"
        assert policy.get_entity_action("EMAIL") == Action.REDACT

    def test_strict_policy(self):
        policy = Policy.strict()
        assert policy.name == "strict"
        assert policy.reversible is True
        assert policy.get_entity_action("EMAIL") == Action.REDACT
        assert policy.get_entity_action("API_KEY") == Action.BLOCK

    def test_enterprise_policy(self):
        policy = Policy.enterprise()
        assert policy.name == "enterprise"
        assert policy.reversible is True
        assert policy.get_entity_action("EMAIL") == Action.REDACT
        assert policy.get_entity_action("API_KEY") == Action.BLOCK

    def test_permissive_policy(self):
        policy = Policy.permissive()
        assert policy.name == "permissive"
        assert policy.reversible is False
        assert policy.get_entity_action("EMAIL") == Action.REDACT
        assert policy.get_entity_action("API_KEY") == Action.BLOCK

    def test_custom_entity_rules(self):
        policy = Policy(
            entity_rules={
                "EMAIL": EntityRule(entity_type="EMAIL", action=Action.PRESERVE),
                "SSN": EntityRule(entity_type="SSN", action=Action.MASK),
            }
        )
        assert policy.get_entity_action("EMAIL") == Action.PRESERVE
        assert policy.get_entity_action("SSN") == Action.MASK
        assert policy.get_entity_action("PHONE") == Action.REDACT

    def test_number_rules(self):
        policy = Policy(
            number_rules={
                "currency": NumberRule(numeric_type="currency", action=Action.SCALE, mode="scale", factor=1.5),
            }
        )
        rule = policy.get_number_rule("currency")
        assert rule is not None
        assert rule.factor == 1.5
        assert policy.get_number_rule("percentage") is None

    def test_date_rule(self):
        policy = Policy(date_rule=DateRule(action=Action.SCALE, mode="shift", shift_days=173))
        assert policy.date_rule is not None
        assert policy.date_rule.shift_days == 173

    def test_actions_are_strings(self):
        assert Action.REDACT == "redact"
        assert Action.BLOCK == "block"
        assert Action.PRESERVE == "preserve"
