import pytest

from aigov_redact.gateway.gateway import PrivacyGateway
from aigov_redact.gateway.session import GatewaySession
from aigov_redact.policy.engine import Policy


class TestPrivacyGateway:
    def test_default_gateway(self):
        gateway = PrivacyGateway()
        assert gateway.policy.name == "default"

    def test_strict_gateway(self):
        gateway = PrivacyGateway(policy="strict")
        assert gateway.policy.name == "strict"
        assert gateway.policy.reversible is True

    def test_enterprise_gateway(self):
        gateway = PrivacyGateway(policy="enterprise")
        assert gateway.policy.name == "enterprise"

    def test_permissive_gateway(self):
        gateway = PrivacyGateway(policy="permissive")
        assert gateway.policy.name == "permissive"

    def test_custom_policy(self):
        policy = Policy(name="custom", reversible=True)
        gateway = PrivacyGateway(policy=policy)
        assert gateway.policy.name == "custom"

    def test_protect_returns_session(self):
        gateway = PrivacyGateway()
        session = gateway.protect("Hello World")
        assert isinstance(session, GatewaySession)


class TestGatewaySession:
    def test_basic_protection(self):
        gateway = PrivacyGateway()
        session = gateway.protect("Email: john@example.com")
        assert session.text != "Email: john@example.com"
        assert "john@example.com" not in session.text

    def test_original_text(self):
        gateway = PrivacyGateway()
        original = "Email: john@example.com"
        session = gateway.protect(original)
        assert session.original == original

    def test_mapping(self):
        gateway = PrivacyGateway()
        session = gateway.protect("Email: john@example.com")
        mapping = session.mapping
        assert len(mapping) > 0

    def test_resolve(self):
        gateway = PrivacyGateway()
        session = gateway.protect("Email: john@example.com")
        resolved = session.resolve(session.text)
        assert "john@example.com" in resolved

    def test_ssn_protection(self):
        gateway = PrivacyGateway()
        session = gateway.protect("SSN: 123-45-6789")
        assert "123-45-6789" not in session.text

    def test_multiple_entities(self):
        gateway = PrivacyGateway()
        session = gateway.protect("Email: john@example.com, SSN: 123-45-6789")
        assert "john@example.com" not in session.text
        assert "123-45-6789" not in session.text
        mapping = session.mapping
        assert len(mapping) >= 2

    def test_user_replacements(self):
        gateway = PrivacyGateway(
            replacements={"Reliance Industries": "<CUST_REL>"}
        )
        session = gateway.protect("Reliance Industries reported results")
        assert "<CUST_REL>" in session.text
        assert "Reliance Industries" not in session.text

    def test_dict_replacements_with_semantic(self):
        gateway = PrivacyGateway(
            replacements={
                "Reliance Industries": {
                    "token": "<CUST_REL>",
                    "semantic": {"industry": "Conglomerate"},
                }
            }
        )
        session = gateway.protect("Reliance Industries reported results")
        assert "<CUST_REL>" in session.text

    def test_block_policy_raises(self):
        policy = Policy(
            entity_rules={
                "API_KEY": __import__("aigov_redact.policy.engine", fromlist=["EntityRule"]).EntityRule(
                    entity_type="API_KEY",
                    action=__import__("aigov_redact.policy.engine", fromlist=["Action"]).Action.BLOCK,
                ),
            }
        )
        gateway = PrivacyGateway(policy=policy)
        with pytest.raises(ValueError, match="BLOCKED"):
            gateway.protect("key: sk-abc123def456ghi789jkl012mno345pqr678stu901")

    def test_scale_numbers(self):
        from aigov_redact.policy.engine import Action, NumberRule

        policy = Policy(
            number_rules={
                "currency": NumberRule(
                    numeric_type="currency",
                    action=Action.SCALE,
                    mode="scale",
                    factor=1.5,
                ),
            }
        )
        gateway = PrivacyGateway(policy=policy)
        session = gateway.protect("Revenue was $100 Million")
        assert "150" in session.text
