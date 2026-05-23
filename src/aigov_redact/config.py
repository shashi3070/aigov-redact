from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from aigov_redact.patterns import PIIDefinition


def find_config(start_path: str | None = None) -> str | None:
    search_dir = Path(start_path).absolute() if start_path else Path.cwd()
    for parent in [search_dir] + list(search_dir.parents):
        for name in (
            ".aigov-redact-config",
            ".aigov-redact-config.json",
            ".aigov-redact-config.yaml",
            ".aigov-redact-config.yml",
        ):
            candidate = parent / name
            if candidate.exists():
                return str(candidate)
        pyproject = parent / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text("utf-8")
                if "[tool.aigov-redact]" in content:
                    return str(pyproject)
            except Exception:
                pass
    return None


def parse_config_header(config_path: str) -> bool:
    return config_path.endswith((".yaml", ".yml"))


def load_config(config_path: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {}

    if config_path is None:
        config_path = find_config()

    if config_path is None or not os.path.exists(config_path):
        return result

    if config_path.endswith(".toml"):
        return _load_toml_config(config_path)

    raw = Path(config_path).read_text("utf-8").strip()

    if config_path.endswith((".yaml", ".yml")):
        try:
            import yaml
            result = yaml.safe_load(raw) or {}
        except ImportError:
            raise ImportError("PyYAML is required to load .yaml config files. Run: pip install aigov-redact[yaml]")
    else:
        result = json.loads(raw)

    return resolve_compliance_profile(result)


def _load_toml_config(path: str) -> dict[str, Any]:
    content = Path(path).read_text("utf-8")
    if "[tool.aigov-redact]" not in content:
        return {}
    section = content.split("[tool.aigov-redact]", 1)[1]
    if "[" in section:
        section = section.split("\n[", 1)[0]

    config: dict[str, Any] = {}
    for line in section.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            try:
                if "." in value:
                    value = float(value)
                else:
                    value = int(value)
            except ValueError:
                pass
            config[key] = value
    return config


def resolve_compliance_profile(config: dict[str, Any]) -> dict[str, Any]:
    profile_name = config.get("compliance_profile")
    if not profile_name:
        return config

    profiles = config.get("compliance_profiles", {})
    profile = profiles.get(profile_name)
    if not profile:
        raise ValueError(f"Compliance profile '{profile_name}' not found in config")

    merged = dict(config)
    for key, value in profile.items():
        if key == "enabled":
            merged.setdefault("pii_types", {})["enabled"] = value
        elif key == "disabled":
            merged.setdefault("pii_types", {})["disabled"] = value
        else:
            merged[key] = value
    return merged


def parse_custom_patterns(config: dict[str, Any]) -> list[PIIDefinition]:
    patterns: list[PIIDefinition] = []
    for item in config.get("custom_patterns", []):
        patterns.append(PIIDefinition(
            name=item.get("name", "CUSTOM"),
            description=item.get("description", "Custom pattern"),
            regex=re.compile(item["pattern"]),
            confidence=float(item.get("confidence", 0.7)),
            severity=item.get("severity", "medium"),
            placeholder=item.get("placeholder", "{CUSTOM}"),
        ))
    return patterns


def merge_config_with_cli(config: dict[str, Any], cli_args: dict[str, Any]) -> dict[str, Any]:
    merged = dict(config)
    for key, value in cli_args.items():
        if value is not None:
            merged[key] = value

    if merged.get("compliance_profile"):
        merged = resolve_compliance_profile(merged)
    return merged
