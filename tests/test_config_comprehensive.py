from __future__ import annotations

import json
import os
import tempfile

import pytest

from aigov_redact.config import (
    get_policy_name,
    load_replacements,
)


class TestGetPolicyName:
    def test_policy_present(self):
        assert get_policy_name({"policy": "enterprise"}) == "enterprise"

    def test_policy_absent(self):
        assert get_policy_name({"placeholder_style": "type"}) is None

    def test_policy_empty_config(self):
        assert get_policy_name({}) is None


class TestLoadReplacements:
    def test_inline_dict(self):
        config = {"replacements": {"Reliance": "<CUST_A>"}}
        assert load_replacements(config) == {"Reliance": "<CUST_A>"}

    def test_no_replacements(self):
        assert load_replacements({}) is None
        assert load_replacements({"policy": "strict"}) is None

    def test_load_json_file(self):
        data = {"Reliance Industries": "<CUST_REL>"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            try:
                result = load_replacements({"replacements": f.name})
            finally:
                f.close()
        os.unlink(f.name)
        assert result == {"Reliance Industries": "<CUST_REL>"}

    def test_load_yaml_file(self):
        yaml_content = "Reliance Industries: <CUST_REL>\nTata: <CUST_T>\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            f.flush()
            try:
                result = load_replacements({"replacements": f.name})
            except ImportError:
                pytest.skip("PyYAML not installed")
            finally:
                f.close()
        os.unlink(f.name)
        assert result == {"Reliance Industries": "<CUST_REL>", "Tata": "<CUST_T>"}

    def test_missing_file_raises(self):
        with pytest.raises(ValueError, match="not found"):
            load_replacements({"replacements": "/no/such/file.yaml"})

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="dict or a file path"):
            load_replacements({"replacements": 123})
