from __future__ import annotations

import pytest

from aigov_redact.gateway.gateway import PrivacyGateway
from aigov_redact.gateway.session import GatewaySession
from aigov_redact.policy.engine import (
    Action,
    DateRule,
    EntityRule,
    NumberRule,
    Policy,
)


# ---------------------------------------------------------------------------
# PrivacyGateway construction & policy selection
# ---------------------------------------------------------------------------
class TestGatewayConstruction:
    def test_default_policy_selected(self):
        assert PrivacyGateway().policy.name == "default"

    def test_strict_policy_selected(self):
        gw = PrivacyGateway(policy="strict")
        assert gw.policy.name == "strict"
        assert gw.policy.reversible is True

    def test_enterprise_policy_selected(self):
        gw = PrivacyGateway(policy="enterprise")
        assert gw.policy.name == "enterprise"

    def test_permissive_policy_selected(self):
        gw = PrivacyGateway(policy="permissive")
        assert gw.policy.name == "permissive"
        assert gw.policy.reversible is False

    def test_unknown_policy_falls_back_to_default(self):
        gw = PrivacyGateway(policy="bogus")
        assert gw.policy.name == "default"

    def test_policy_object_used_directly(self):
        policy = Policy(name="custom", reversible=True)
        gw = PrivacyGateway(policy=policy)
        assert gw.policy is policy

    def test_reversible_override(self):
        gw = PrivacyGateway(policy="permissive", reversible=True)
        assert gw.policy.reversible is True

    def test_detector_exposed(self):
        gw = PrivacyGateway()
        assert gw.detector is not None

    def test_enabled_types_restrict_detection(self):
        gw = PrivacyGateway(enabled_types=["EMAIL"])
        session = gw.protect("Email a@b.com and SSN 123-45-6789")
        assert "a@b.com" not in session.text
        assert "123-45-6789" in session.text  # SSN not in enabled_types


# ---------------------------------------------------------------------------
# GatewaySession core behaviour (protect -> resolve)
# ---------------------------------------------------------------------------
class TestGatewaySessionCore:
    def test_protect_returns_session_instance(self):
        assert isinstance(PrivacyGateway().protect("hi"), GatewaySession)

    def test_original_preserved(self):
        text = "Email john@example.com"
        session = PrivacyGateway().protect(text)
        assert session.original == text

    def test_refuses_empty_input(self):
        session = PrivacyGateway().protect("")
        assert session.text == ""
        assert session.original == ""

    def test_no_pii_is_unchanged(self):
        session = PrivacyGateway().protect("Hello plain world")
        assert session.text == "Hello plain world"

    def test_email_tokenized(self):
        session = PrivacyGateway(policy="strict").protect("Email a@b.com")
        assert "a@b.com" not in session.text
        assert "<EMAIL_" in session.text

    def test_multiple_entities_all_tokenized(self):
        session = PrivacyGateway(policy="strict").protect(
            "Email a@b.com, SSN 123-45-6789"
        )
        assert "a@b.com" not in session.text
        assert "123-45-6789" not in session.text
        assert len(session.mapping) >= 2

    def test_resolve_restores_originals(self):
        text = "Email a@b.com and SSN 123-45-6789"
        session = PrivacyGateway(policy="strict").protect(text)
        resolved = session.resolve(session.text)
        assert "a@b.com" in resolved
        assert "123-45-6789" in resolved

    def test_resolve_identity_on_fresh_text(self):
        session = PrivacyGateway(policy="strict").protect("Email a@b.com")
        assert session.resolve("no tokens here") == "no tokens here"

    def test_mapping_contains_token_to_original(self):
        session = PrivacyGateway(policy="strict").protect("Email a@b.com")
        mapping = session.mapping
        assert len(mapping) == 1
        token = next(iter(mapping))
        assert mapping[token] == "a@b.com"


# ---------------------------------------------------------------------------
# resolve_json — restore values inside structured JSON responses
# ---------------------------------------------------------------------------
class TestGatewayResolveJson:
    def test_resolve_json_dict(self):
        session = PrivacyGateway(policy="strict").protect("user a@b.com")
        token = next(iter(session.mapping))
        payload = {"user": token, "note": "seen"}
        resolved = session.resolve_json(payload)
        assert resolved["user"] == "a@b.com"
        assert resolved["note"] == "seen"

    def test_resolve_json_list(self):
        session = PrivacyGateway(policy="strict").protect("a@b.com")
        token = next(iter(session.mapping))
        resolved = session.resolve_json([token, "x"])
        assert "a@b.com" in resolved

    def test_resolve_json_nested(self):
        session = PrivacyGateway(policy="strict").protect("a@b.com")
        token = next(iter(session.mapping))
        payload = {"a": {"b": [token]}}
        resolved = session.resolve_json(payload)
        assert resolved["a"]["b"] == ["a@b.com"]

    def test_resolve_json_preserves_plain_values(self):
        session = PrivacyGateway(policy="strict").protect("a@b.com")
        payload = {"count": 5, "flag": True, "name": "Reliance"}
        resolved = session.resolve_json(payload)
        assert resolved == payload


# ---------------------------------------------------------------------------
# Every protection action against a custom policy
# ---------------------------------------------------------------------------
class TestGatewayActions:
    def _gateway_for_action(self, action: Action) -> PrivacyGateway:
        policy = Policy(
            entity_rules={"EMAIL": EntityRule(entity_type="EMAIL", action=action)}
        )
        return PrivacyGateway(policy=policy)

    def test_action_mask(self):
        session = self._gateway_for_action(Action.MASK).protect("Email a@b.com")
        assert "a@b.com" not in session.text
        assert "*" in session.text

    def test_action_hash(self):
        session = self._gateway_for_action(Action.HASH).protect("Email a@b.com")
        assert "a@b.com" not in session.text
        assert "<EMAIL_" in session.text

    def test_action_remove(self):
        session = self._gateway_for_action(Action.REMOVE).protect("Email a@b.com")
        assert "Email " == session.text

    def test_action_preserve(self):
        session = self._gateway_for_action(Action.PRESERVE).protect("Email a@b.com")
        assert session.text == "Email a@b.com"

    def test_action_tokenize(self):
        session = self._gateway_for_action(Action.TOKENIZE).protect("Email a@b.com")
        assert "a@b.com" not in session.text
        assert "<EMAIL_" in session.text

    def test_action_allow(self):
        session = self._gateway_for_action(Action.ALLOW).protect("Email a@b.com")
        assert session.text == "Email a@b.com"

    def test_action_block_raises(self):
        with pytest.raises(ValueError, match="BLOCKED"):
            self._gateway_for_action(Action.BLOCK).protect("Email a@b.com")

    def test_block_error_mentions_type(self):
        with pytest.raises(ValueError, match="EMAIL"):
            self._gateway_for_action(Action.BLOCK).protect("Email a@b.com")


# ---------------------------------------------------------------------------
# Secrets blocked by pre-built policies
# ---------------------------------------------------------------------------
class TestGatewaySecrets:
    @pytest.mark.parametrize(
        "secret",
        [
            "sk-abc123def456ghi789jkl012mno345",  # OpenAI-style
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        ],
    )
    def test_api_key_blocked_in_strict(self, secret):
        gw = PrivacyGateway(policy="strict")
        with pytest.raises(ValueError, match="BLOCKED"):
            gw.protect(f"key {secret}")

    def test_password_blocked_in_strict(self):
        gw = PrivacyGateway(policy="strict")
        with pytest.raises(ValueError):
            gw.protect("password: hunter2 hmm")

    def test_private_key_blocked_in_strict(self):
        gw = PrivacyGateway(policy="strict")
        with pytest.raises(ValueError):
            gw.protect("-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----")

    def test_enterprise_blocks_api_key(self):
        gw = PrivacyGateway(policy="enterprise")
        with pytest.raises(ValueError, match="BLOCKED"):
            gw.protect("key sk-abc123def456ghi789jkl012mno345")


# ---------------------------------------------------------------------------
# Custom entity replacements
# ---------------------------------------------------------------------------
class TestGatewayReplacements:
    def test_simple_string_replacement(self):
        gw = PrivacyGateway(replacements={"Reliance Industries": "<CUST_REL>"})
        session = gw.protect("Reliance Industries grew 10%")
        assert "<CUST_REL>" in session.text
        assert "Reliance Industries" not in session.text

    def test_multiple_replacements(self):
        gw = PrivacyGateway(
            replacements={
                "Reliance Industries": "<CUST_A>",
                "Tata Consultancy": "<CUST_B>",
            }
        )
        session = gw.protect("Reliance Industries and Tata Consultancy merged")
        assert "<CUST_A>" in session.text
        assert "<CUST_B>" in session.text

    def test_dict_replacement_with_semantic(self):
        gw = PrivacyGateway(
            replacements={
                "Reliance Industries": {
                    "token": "<CUST_REL>",
                    "semantic": {"industry": "Conglomerate", "region": "India"},
                }
            }
        )
        session = gw.protect("Reliance Industries reported")
        assert "<CUST_REL>" in session.text

    def test_no_match_leaves_text_alone(self):
        gw = PrivacyGateway(replacements={"Reliance Industries": "<CUST_REL>"})
        session = gw.protect("Tata reported results")
        assert "Tata reported results" == session.text

    def test_replacement_resolves_back(self):
        gw = PrivacyGateway(replacements={"Reliance Industries": "<CUST_REL>"})
        session = gw.protect("Reliance Industries reported")
        assert "Reliance Industries" in session.resolve(session.text)


# ---------------------------------------------------------------------------
# Number transformations driven by policy
# ---------------------------------------------------------------------------
class TestGatewayNumbers:
    def _num_policy(self, mode: str = "scale", factor: float | None = 1.5):
        return Policy(
            number_rules={
                "currency": NumberRule(
                    numeric_type="currency", action=Action.SCALE, mode=mode, factor=factor
                )
            }
        )

    def test_scale_applies(self):
        session = PrivacyGateway(policy=self._num_policy()).protect(
            "Revenue was $100 Million"
        )
        assert "150" in session.text

    def test_scale_is_resolvable(self):
        session = PrivacyGateway(policy=self._num_policy()).protect(
            "Revenue was $100 Million"
        )
        resolved = session.resolve(session.text)
        # both the number rounds through register_number_op
        assert "$" in resolved

    def test_range_mode(self):
        session = PrivacyGateway(policy=self._num_policy(mode="range")).protect(
            "Revenue was $150 Million"
        )
        assert "-" in session.text

    def test_random_scale(self):
        policy = Policy(
            number_rules={
                "currency": NumberRule(
                    numeric_type="currency",
                    action=Action.SCALE,
                    mode="random_scale",
                    min_factor=0.8,
                    max_factor=1.4,
                )
            }
        )
        session = PrivacyGateway(policy=policy).protect("Revenue was $100 Million")
        assert "$" in session.text

    def test_numbers_preserved_by_default(self):
        # No number rules -> numbers untouched
        session = PrivacyGateway(policy="enterprise").protect(
            "Revenue was $100 Million"
        )
        assert "$100 Million" in session.text


# ---------------------------------------------------------------------------
# Date transformations driven by policy
# ---------------------------------------------------------------------------
class TestGatewayDates:
    def _date_policy(self):
        return Policy(date_rule=DateRule(action=Action.SCALE, mode="shift", shift_days=173))

    def test_date_shift_applies(self):
        # disable DATE_OF_BIRTH so the date transformer (not PII) handles the date
        gw = PrivacyGateway(
            policy=self._date_policy(), disabled_types=["DATE_OF_BIRTH"]
        )
        session = gw.protect("meeting scheduled for 2026-05-20")
        assert "2026-05-20" not in session.text
        assert "2026-" in session.text

    def test_date_preserved_by_default(self):
        # no date rule -> date untouched (and not PII here)
        gw = PrivacyGateway(policy="enterprise", disabled_types=["DATE_OF_BIRTH"])
        session = gw.protect("meeting scheduled for 2026-05-20")
        assert "2026-05-20" in session.text

    def test_date_shift_resolvable(self):
        gw = PrivacyGateway(
            policy=self._date_policy(), disabled_types=["DATE_OF_BIRTH"]
        )
        session = gw.protect("meeting scheduled for 2026-05-20")
        resolved = session.resolve(session.text)
        assert "2026-05-20" in resolved


# ---------------------------------------------------------------------------
# Combined end-to-end: PII + numbers + dates all in one session
# ---------------------------------------------------------------------------
class TestGatewayEndToEnd:
    def test_full_pipeline_roundtrip(self):
        policy = Policy(
            entity_rules={
                "EMAIL": EntityRule(entity_type="EMAIL", action=Action.REDACT),
                "SSN": EntityRule(entity_type="SSN", action=Action.REDACT),
            },
            number_rules={
                "currency": NumberRule(
                    numeric_type="currency", action=Action.SCALE, mode="scale", factor=2.0
                )
            },
            date_rule=DateRule(action=Action.SCALE, mode="shift", shift_days=5),
        )
        gw = PrivacyGateway(policy=policy)
        original = "Client a@b.com, SSN 123-45-6789, paid $50, born 2000-01-01"
        session = gw.protect(original)

        # Everything sensitive is gone from protected text
        assert "a@b.com" not in session.text
        assert "123-45-6789" not in session.text

        # LLM echoes the safe text back
        resolved = session.resolve(session.text)
        assert "a@b.com" in resolved
        assert "123-45-6789" in resolved
