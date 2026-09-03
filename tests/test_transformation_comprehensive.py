from __future__ import annotations

import pytest

from aigov_redact.mapping.vault import MappingVault
from aigov_redact.transformation.dates import DateTransformer
from aigov_redact.transformation.numbers import NumberTransformer
from aigov_redact.transformation.semantic import SemanticAbstracter


# ---------------------------------------------------------------------------
# NumberTransformer: scale / random_scale / range / reverse
# ---------------------------------------------------------------------------
class TestScale:
    @pytest.mark.parametrize(
        "text,factor,expected_substr",
        [
            ("Revenue $100 Million", 1.5, "150"),
            ("₹48.5 Cr", 1.37, "66"),
            ("€200", 2.0, "400"),
            ("£50 K", 3.0, "150"),
            ("¥300 Billion", 0.5, "150"),
        ],
    )
    def test_scale_currencies(self, text, factor, expected_substr):
        assert expected_substr in NumberTransformer().scale(text, factor)

    def test_scale_multiplies_exactly(self):
        assert NumberTransformer().scale("$10", 2.0) == "$20.0"

    def test_scale_decimal_precision(self):
        result = NumberTransformer().scale("$10.10", 1.5)
        assert "15.15" in result

    def test_scale_percentage(self):
        result = NumberTransformer().scale("growth 10%", 1.5)
        assert "15.0" in result

    def test_scale_billion(self):
        result = NumberTransformer().scale("market $2 Billion", 2.0)
        assert "4.0" in result

    def test_scale_plain_number(self):
        result = NumberTransformer().scale("100 Million users", 2.0)
        assert "200.0" in result

    def test_scale_does_not_touch_phone_like_numbers(self):
        # "123-45-6789" should not be scaled (no unit suffix)
        result = NumberTransformer().scale("SSN 123-45-6789", 2.0)
        assert "123-45-6789" in result


class TestRandomScale:
    def test_within_bounds(self):
        transformer = NumberTransformer()
        for _ in range(20):
            result = transformer.random_scale("$100", 0.5, 2.0)
            value = float(result.replace("$", ""))
            assert 50.0 <= value <= 200.0

    def test_uses_vault(self):
        vault = MappingVault()
        transformer = NumberTransformer(vault)
        transformer.random_scale("$100", 0.9, 1.1)
        assert len(vault.export_mapping()) == 0  # numbers stored internally

    def test_default_bounds(self):
        transformer = NumberTransformer()
        result = transformer.random_scale("$100")
        value = float(result.replace("$", ""))
        assert 80.0 <= value <= 140.0


class TestRangeTransform:
    def test_generates_range(self):
        result = NumberTransformer().range_transform("Revenue $150 Million")
        assert "-" in result

    def test_low_high_bounds(self):
        result = NumberTransformer().range_transform("$150")
        # 150 -> magnitude 100 -> low 100, high 200
        assert "100-200" in result

    def test_small_number(self):
        result = NumberTransformer().range_transform("$5")
        assert "0-1" in result or "5-6" in result


class TestReverse:
    def test_reverse_restores_scale(self):
        vault = MappingVault()
        t = NumberTransformer(vault)
        scaled = t.scale("$100", 2.0)
        assert "$200.0" in scaled
        assert "$100" in t.reverse(scaled)

    def test_reverse_restores_percentage(self):
        vault = MappingVault()
        t = NumberTransformer(vault)
        scaled = t.scale("growth 10%", 1.5)
        assert "15.0 %" in scaled or "15.0%" in scaled
        reversed_result = t.reverse(scaled)
        assert "10" in reversed_result

    def test_reverse_untouched_when_no_vault(self):
        t = NumberTransformer()
        assert t.reverse("$150") == "$150"

    def test_reverse_unknown_value_preserved(self):
        vault = MappingVault()
        t = NumberTransformer(vault)
        t.scale("$100", 2.0)  # only 100->200 registered
        assert t.reverse("$999") == "$999"  # 999 not in vault


class TestPercentile:
    def test_percentile_is_identity(self):
        t = NumberTransformer()
        assert t.percentile_transform("$100") == "$100"


# ---------------------------------------------------------------------------
# DateTransformer: shift / reverse for all supported formats
# ---------------------------------------------------------------------------
class TestDateShift:
    def test_shift_ymd(self):
        result = DateTransformer().shift("2026-05-20", 5)
        assert result == "2026-05-25"

    def test_shift_dmy(self):
        result = DateTransformer().shift("20/05/2026", 5)
        assert result == "25/05/2026"

    def test_shift_mdy(self):
        result = DateTransformer().shift("05-20-2026", 5)
        assert result == "05-25-2026"

    def test_shift_negative_days(self):
        result = DateTransformer().shift("2026-05-20", -10)
        assert result == "2026-05-10"

    def test_shift_month_boundary(self):
        result = DateTransformer().shift("2026-01-30", 5)
        assert result == "2026-02-04"

    def test_shift_year_boundary(self):
        result = DateTransformer().shift("2026-12-30", 5)
        assert result == "2027-01-04"

    def test_shift_invalid_date_preserved(self):
        # 2026-02-30 does not exist; strptime fails -> preserved
        result = DateTransformer().shift("2026-02-30", 5)
        assert result == "2026-02-30"


class TestDateReverse:
    def test_reverse_restores_ymd(self):
        vault = MappingVault()
        t = DateTransformer(vault)
        shifted = t.shift("2026-05-20", 5)
        assert t.reverse(shifted) == "2026-05-20"

    def test_reverse_preserves_dmy(self):
        # reverse only re-implements the YMD pattern; DMY stays as-is
        vault = MappingVault()
        t = DateTransformer(vault)
        shifted = t.shift("20/05/2026", 5)
        assert t.reverse(shifted) == shifted

    def test_reverse_without_vault_identity(self):
        t = DateTransformer()
        assert t.reverse("2026-05-25") == "2026-05-25"

    def test_reverse_unknown_date_preserved(self):
        vault = MappingVault()
        t = DateTransformer(vault)
        t.shift("2026-05-20", 5)
        assert t.reverse("1999-01-01") == "1999-01-01"


# ---------------------------------------------------------------------------
# SemanticAbstracter
# ---------------------------------------------------------------------------
class TestSemanticAbstract:
    def test_multiple_replacements(self):
        a = SemanticAbstracter(
            {
                "Reliance Industries": "<CUST_A>",
                "Tata Consultancy": "<CUST_B>",
            }
        )
        result = a.abstract("Reliance Industries bought Tata Consultancy")
        assert result == "<CUST_A> bought <CUST_B>"

    def test_dict_replacement_with_default_token(self):
        a = SemanticAbstracter({"Reliance Industries": {"semantic": {"x": "y"}}})
        result = a.abstract("Reliance Industries")
        assert result.startswith("<ENTITY_")

    def test_empty_replacements(self):
        a = SemanticAbstracter()
        assert a.abstract("hello") == "hello"

    def test_partial_overlap(self):
        # Longer key matched even when a shorter prefix is present
        a = SemanticAbstracter({"Reliance Industries": "<REL>", "Reliance": "<SHORT>"})
        result = a.abstract("Reliance Industries grew")
        assert "Reliance Industries" not in result

    def test_get_metadata_missing(self):
        a = SemanticAbstracter({"Reliance Industries": "<REL>"})
        assert a.get_metadata("Tata") is None


# ---------------------------------------------------------------------------
# MappingVault: new explicit_token + bool semantics
# ---------------------------------------------------------------------------
class TestMappingVaultExplicit:
    def test_explicit_token_resolvable(self):
        vault = MappingVault()
        vault.register("ENTITY", "Reliance Industries", explicit_token="<CUST_REL>")
        assert vault.resolve("<CUST_REL>") == "Reliance Industries"

    def test_explicit_token_in_export(self):
        vault = MappingVault()
        vault.register("ENTITY", "Reliance Industries", explicit_token="<CUST_REL>")
        assert vault.export_mapping() == {"<CUST_REL>": "Reliance Industries"}

    def test_generated_token_still_default(self):
        vault = MappingVault()
        token = vault.register("EMAIL", "a@b.com")
        assert token.startswith("<EMAIL_")

    def test_bool_semantics(self):
        # bool(vault) is True even when empty (guards rely on this)
        vault = MappingVault()
        assert bool(vault) is True
        assert len(vault) == 0

    def test_contains(self):
        vault = MappingVault()
        token = vault.register("EMAIL", "a@b.com")
        assert token in vault
        assert "<NOPE_12345678>" not in vault

    def test_duplicate_explicit_returns_same(self):
        vault = MappingVault()
        vault.register("ENTITY", "Reliance", explicit_token="<CUST_REL>")
        token = vault.register("ENTITY", "Reliance")
        assert token == "<CUST_REL>"
