from __future__ import annotations

import json
import os
import tempfile

import pytest

from aigov_redact.config import (
    find_config,
    load_config,
    merge_config_with_cli,
    parse_custom_patterns,
    resolve_compliance_profile,
)


class TestLoadConfig:
    def test_load_json_config(self):
        config_data = {
            "pii_types": {"disabled": ["IPV4", "IPV6"]},
            "placeholder_style": "type",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config_data, f)
            f.flush()
            result = load_config(f.name)
        os.unlink(f.name)
        assert result["pii_types"]["disabled"] == ["IPV4", "IPV6"]
        assert result["placeholder_style"] == "type"

    def test_load_config_nonexistent(self):
        result = load_config("/nonexistent/config.json")
        assert result == {}

    def test_load_config_none(self):
        result = load_config(None)
        assert result == {}

    def test_custom_patterns(self):
        config = {
            "custom_patterns": [
                {
                    "name": "TEST_ID",
                    "pattern": "TEST-\\d{4}",
                    "confidence": 0.8,
                    "severity": "medium",
                    "placeholder": "{TEST_ID}",
                    "description": "test",
                }
            ]
        }
        patterns = parse_custom_patterns(config)
        assert len(patterns) == 1
        assert patterns[0].name == "TEST_ID"
        assert patterns[0].confidence == 0.8

    def test_load_yaml_config(self):
        yaml_content = """
pii_types:
  disabled:
    - IPV4
    - IPV6
placeholder_style: type
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            f.flush()
            try:
                result = load_config(f.name)
                assert result["pii_types"]["disabled"] == ["IPV4", "IPV6"]
            except ImportError:
                pytest.skip("PyYAML not installed")
        os.unlink(f.name)

    def test_find_config(self):
        cfg = find_config()
        assert cfg is None or os.path.exists(cfg)


class TestComplianceProfile:
    def test_no_profile_returns_unchanged(self):
        cfg = {"placeholder_style": "type"}
        result = resolve_compliance_profile(cfg)
        assert result == cfg

    def test_unknown_profile_raises(self):
        cfg = {"compliance_profile": "bogus", "compliance_profiles": {"hipaa": {}}}
        with pytest.raises(ValueError, match="not found"):
            resolve_compliance_profile(cfg)

    def test_active_profile_merges_enabled(self):
        cfg = {
            "compliance_profile": "hipaa",
            "compliance_profiles": {
                "hipaa": {
                    "enabled": ["SSN", "PHONE", "EMAIL"],
                    "placeholder_style": "hash",
                }
            },
        }
        result = resolve_compliance_profile(cfg)
        assert result["pii_types"]["enabled"] == ["SSN", "PHONE", "EMAIL"]
        assert result["placeholder_style"] == "hash"

    def test_active_profile_merges_disabled(self):
        cfg = {
            "compliance_profile": "gdpr",
            "compliance_profiles": {
                "gdpr": {
                    "disabled": ["IPV4"],
                    "ner_enabled": True,
                }
            },
        }
        result = resolve_compliance_profile(cfg)
        assert result["pii_types"]["disabled"] == ["IPV4"]
        assert result["ner_enabled"] is True

    def test_active_profile_overrides_top_level_keys(self):
        cfg = {
            "compliance_profile": "pci",
            "compliance_profiles": {
                "pci": {"placeholder_style": "hash"},
            },
            "placeholder_style": "type",
        }
        result = resolve_compliance_profile(cfg)
        assert result["placeholder_style"] == "hash"

    def test_merge_config_with_cli_resolves_profile(self):
        cfg = {
            "compliance_profiles": {
                "hipaa": {"enabled": ["SSN"]},
            },
        }
        result = merge_config_with_cli(cfg, {"compliance_profile": "hipaa"})
        assert result["pii_types"]["enabled"] == ["SSN"]

    def test_merge_config_with_cli_ignores_none(self):
        result = merge_config_with_cli({"foo": "bar"}, {"compliance_profile": None})
        assert result == {"foo": "bar"}
