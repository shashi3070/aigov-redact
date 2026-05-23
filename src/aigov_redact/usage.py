from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _history_path() -> Path:
    return Path.home() / ".prompt-sanitizer" / "history.jsonl"


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


def record_usage(command: str, **kwargs: Any) -> None:
    path = _history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = UsageRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        command=command,
        **kwargs,
    )
    with open(str(path), "a", encoding="utf-8") as f:
        f.write(record.model_dump_json() + "\n")


def get_history(limit: int = 50) -> list[UsageRecord]:
    path = _history_path()
    if not path.exists():
        return []
    records: list[UsageRecord] = []
    with open(str(path), "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(UsageRecord.model_validate_json(line))
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
