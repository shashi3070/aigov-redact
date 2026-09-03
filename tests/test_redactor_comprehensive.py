from __future__ import annotations

from aigov_redact.mapping.vault import MappingVault
from aigov_redact.redactor import redact


class TestRedactReversible:
    def test_reversible_default_not_set(self):
        r = redact("Email a@b.com")
        assert r.mode == "replace"
        assert r.mapping is None

    def test_reversible_flag_produces_tokens(self):
        r = redact("Email a@b.com", reversible=True)
        assert r.mode == "reversible"
        assert "a@b.com" not in r.text
        assert "<EMAIL_" in r.text

    def test_reversible_mapping_populated(self):
        r = redact("Email a@b.com", reversible=True)
        assert r.mapping is not None
        token = next(iter(r.mapping))
        assert r.mapping[token] == "a@b.com"

    def test_reversible_multiple_entities(self):
        r = redact("Email a@b.com, SSN 123-45-6789", reversible=True)
        assert r.mapping is not None
        assert len(r.mapping) == 2

    def test_reversible_uses_external_vault(self):
        vault = MappingVault()
        r = redact("Email a@b.com", reversible=True, mapping=vault)
        assert r.mapping is not None
        # same vault now holds the mapping
        assert len(vault.export_mapping()) == 1

    def test_reversible_in_place_vault_shared(self):
        # Two calls with the same vault -> deterministic tokens
        vault = MappingVault()
        r1 = redact("Email a@b.com", mapping=vault, reversible=True)
        token1 = next(iter(r1.mapping))
        r2 = redact("Email a@b.com", mapping=vault, reversible=True)
        token2 = next(iter(r2.mapping))
        assert token1 == token2

    def test_reversible_does_not_break_non_reversible_modes(self):
        r = redact("Email a@b.com", mode="mask", reversible=False)
        assert r.mode == "mask"
        assert r.mapping is None

    def test_reversible_no_pii(self):
        r = redact("hello plain", reversible=True)
        assert r.mapping == {}


class TestRedactResultFields:
    def test_risk_fields_default_none(self):
        r = redact("Email a@b.com")
        assert r.risk_score is None
        assert r.risk_details is None

    def test_risk_fields_assignable(self):
        r = redact("Email a@b.com")
        r.risk_score = 0.7
        r.risk_details = {"high": 1}
        assert r.risk_score == 0.7
        assert r.risk_details == {"high": 1}


class TestRedactCustomPatterns:
    def test_custom_definition(self):
        import re

        from aigov_redact.patterns import PIIDefinition

        emp_id = PIIDefinition(
            name="EMP_ID",
            description="Employee id",
            regex=re.compile(r"EMP-\d{6}"),
            confidence=0.95,
            severity="medium",
            placeholder="{EMP_ID}",
        )
        r = redact("id EMP-123456", custom_patterns=[emp_id])
        assert "{EMP_ID}" in r.text

    def test_custom_pattern_with_reversible(self):
        import re

        from aigov_redact.patterns import PIIDefinition

        emp_id = PIIDefinition(
            name="EMP_ID",
            description="Employee id",
            regex=re.compile(r"EMP-\d{6}"),
            confidence=0.95,
            severity="medium",
            placeholder="{EMP_ID}",
        )
        r = redact("id EMP-123456", custom_patterns=[emp_id], reversible=True)
        assert "<EMP_ID_" in r.text
        assert r.mapping is not None
