from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel


_HOME_PATH = Path.home() / ".aigov-redact" / "history.jsonl"
_CWD_PATH = Path.cwd() / ".aigov-redact" / "history.jsonl"


def _resolve_paths(history_path: str | None = None) -> list[Path]:
    if history_path:
        return [Path(history_path)]
    return [_HOME_PATH, _CWD_PATH]


class UsageRecord(BaseModel):
    timestamp: str = ""
    command: str = ""
    source: str = ""
    file_path: str | None = None
    entity_count: int = 0
    entity_types: list[str] = []
    mode: str = ""
    ner_enabled: bool = False
    compliance_profile: str | None = None


def record_usage(command: str, history_path: str | None = None, **kwargs: Any) -> None:
    paths = _resolve_paths(history_path)
    record = UsageRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        command=command,
        **kwargs,
    )
    line = record.model_dump_json() + "\n"
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(path), "a", encoding="utf-8") as f:
            f.write(line)


def get_history(limit: int = 50, history_path: str | None = None) -> list[UsageRecord]:
    paths = _resolve_paths(history_path)
    seen: set[str] = set()
    records: list[UsageRecord] = []
    for path in paths:
        if not path.exists():
            continue
        with open(str(path), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and line not in seen:
                    seen.add(line)
                    records.append(UsageRecord.model_validate_json(line))
    records.sort(key=lambda r: r.timestamp)
    return records[-limit:]


def get_history_summary(records: list[UsageRecord]) -> dict[str, Any]:
    total = len(records)
    command_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for r in records:
        command_counts[r.command] = command_counts.get(r.command, 0) + 1
        for t in r.entity_types:
            type_counts[t] = type_counts.get(t, 0) + 1
    return {
        "total_runs": total,
        "commands": command_counts,
        "entity_types_detected": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
    }
