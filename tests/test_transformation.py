from aigov_redact.mapping.vault import MappingVault
from aigov_redact.transformation.dates import DateTransformer
from aigov_redact.transformation.numbers import NumberTransformer
from aigov_redact.transformation.semantic import SemanticAbstracter


class TestNumberTransformer:
    def test_scale_currency(self):
        transformer = NumberTransformer()
        result = transformer.scale("Revenue was $100 Million", 1.5)
        assert "150" in result
        assert "$" in result

    def test_scale_with_prefix(self):
        transformer = NumberTransformer()
        result = transformer.scale("Profit was ₹48.5 Cr", 1.37)
        assert "66" in result

    def test_scale_with_vault(self):
        vault = MappingVault()
        transformer = NumberTransformer(vault)
        result = transformer.scale("Revenue was $100 Million", 1.5)
        assert "150" in result

    def test_range_transform(self):
        transformer = NumberTransformer()
        result = transformer.range_transform("Revenue was $150 Million")
        assert "-" in result

    def test_reverse_with_vault(self):
        vault = MappingVault()
        transformer = NumberTransformer(vault)
        result = transformer.scale("Revenue was $100", 1.5)
        assert "150" in result
        reversed_result = transformer.reverse(result)
        assert "100" in reversed_result

    def test_no_vault_reverse(self):
        transformer = NumberTransformer()
        result = transformer.reverse("Revenue was $150")
        assert result == "Revenue was $150"


class TestDateTransformer:
    def test_shift_ymd(self):
        transformer = DateTransformer()
        result = transformer.shift("DOB: 1990-01-15", 173)
        assert "1990-01-15" not in result
        assert "1990-" in result

    def test_shift_dmy(self):
        transformer = DateTransformer()
        result = transformer.shift("Date: 15/01/1990", 173)
        assert "15/01/1990" not in result

    def test_shift_with_vault(self):
        vault = MappingVault()
        transformer = DateTransformer(vault)
        result = transformer.shift("DOB: 1990-01-15", 173)
        assert "1990-01-15" not in result

    def test_reverse_with_vault(self):
        vault = MappingVault()
        transformer = DateTransformer(vault)
        result = transformer.shift("DOB: 1990-01-15", 173)
        reversed_result = transformer.reverse(result)
        assert "1990-01-15" in reversed_result


class TestSemanticAbstracter:
    def test_simple_replacement(self):
        abstracter = SemanticAbstracter({"Reliance Industries": "<CUST_REL>"})
        result = abstracter.abstract("Reliance Industries reported results")
        assert result == "<CUST_REL> reported results"

    def test_dict_replacement(self):
        abstracter = SemanticAbstracter({
            "Reliance Industries": {
                "token": "<CUST_REL>",
                "semantic": {"industry": "Conglomerate"},
            }
        })
        result = abstracter.abstract("Reliance Industries reported results")
        assert result == "<CUST_REL> reported results"

    def test_no_match(self):
        abstracter = SemanticAbstracter({"Reliance Industries": "<CUST_REL>"})
        result = abstracter.abstract("Tata reported results")
        assert result == "Tata reported results"

    def test_get_metadata(self):
        abstracter = SemanticAbstracter({
            "Reliance Industries": {
                "token": "<CUST_REL>",
                "semantic": {"industry": "Conglomerate"},
            }
        })
        metadata = abstracter.get_metadata("Reliance Industries")
        assert metadata is not None
        assert metadata["industry"] == "Conglomerate"

    def test_no_metadata(self):
        abstracter = SemanticAbstracter({"Reliance Industries": "<CUST_REL>"})
        metadata = abstracter.get_metadata("Reliance Industries")
        assert metadata is None
